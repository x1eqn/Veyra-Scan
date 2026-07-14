from __future__ import annotations

import ctypes
import datetime as dt
import hashlib
import os
import string
from pathlib import Path
from typing import Callable

from .exe_rules import classify_folder
from .file_classifier import classify_file
from .static_models import FileInventoryItem, InventoryResult, InventoryStats


LogFn = Callable[[str, str], None]

DRIVE_FIXED = 3
DEFAULT_MAX_SUPPORTED_FILES = 25_000
DEFAULT_MAX_FOLDERS_PER_ROOT = 50_000
PROGRESS_EVERY_FOLDERS = 2_000
MAX_NOTES = 80

# Folders that are extremely noisy for a local review scanner and frequently make
# a full C:\ traversal look frozen. The scanner still covers high-value user,
# launcher, startup, and program locations separately.
SKIP_DIR_NAMES = {
    "$recycle.bin",
    "$windows.~bt",
    "$windows.~ws",
    "system volume information",
    "recovery",
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    "cache",
    "caches",
    "tmp",
    "temp",
}

# Path fragments that are known to be huge and low-value for this tool. These are
# skipped only during broad inventory traversal, not when the user/test supplies
# explicit roots.
LOW_VALUE_PATH_FRAGMENTS = (
    "\\windows\\winsxs",
    "\\windows\\servicing",
    "\\windows\\softwaredistribution",
    "\\windows\\installer",
    "\\programdata\\package cache",
    "\\appdata\\local\\packages",
    "\\appdata\\local\\microsoft\\windows\\inetcache",
    "\\appdata\\local\\microsoft\\windows\\webcache",
)


class InventoryScanner:
    def __init__(self, log: LogFn | None = None, roots: list[Path] | None = None, max_files: int | None = None, full_drive_scan: bool | None = None):
        self.log = log or (lambda _tag, _msg: None)
        self.roots = roots
        self.max_files = max_files if max_files is not None else (None if roots is not None else _env_int("XIEN_CONTROL_MAX_FILES", DEFAULT_MAX_SUPPORTED_FILES))
        self.max_folders_per_root = _env_int("XIEN_CONTROL_MAX_FOLDERS_PER_ROOT", DEFAULT_MAX_FOLDERS_PER_ROOT)
        self.full_drive_scan = _env_flag("XIEN_CONTROL_FULL_DRIVE_SCAN") if full_drive_scan is None else full_drive_scan
        self.stats = InventoryStats()
        self._items: list[FileInventoryItem] = []
        self._seen_realpaths: set[str] = set()
        self._explicit_roots = roots is not None

    def scan(self) -> InventoryResult:
        self.log("SCAN", "Inventory phase started")
        roots = self._candidate_roots()
        if self.full_drive_scan:
            self.log("SCAN", "Full drive inventory enabled by XIEN_CONTROL_FULL_DRIVE_SCAN=1")
        else:
            self.log("SCAN", f"Focused inventory roots: {len(roots)}")
        for root in roots:
            self._scan_root(root)
            if self.max_files and len(self._items) >= self.max_files:
                self._note(f"inventory stopped after file limit: {self.max_files}")
                self.log("WARN", f"Inventory file limit reached: {self.max_files}")
                break
        self.stats.supported_files = len(self._items)
        self.log("SCAN", f"Inventory complete: {self.stats.files_seen} files seen, {self.stats.supported_files} supported files")
        return InventoryResult(items=self._items, stats=self.stats)

    def _candidate_roots(self) -> list[Path]:
        if self.roots is not None:
            roots = list(self.roots)
        else:
            roots = self._focused_default_roots()
            if self.full_drive_scan:
                # Root drives are deliberately appended last and only when explicitly
                # enabled. The normal default is focused and fast, because a raw C:\
                # walk can contain hundreds of thousands of folders.
                roots.extend(self._fixed_drive_roots())
        out: list[Path] = []
        seen: set[str] = set()
        for root in roots:
            try:
                resolved = root.resolve()
            except OSError:
                resolved = root
            key = str(resolved).lower()
            if key in seen or not resolved.exists() or not resolved.is_dir():
                continue
            # Avoid swallowing high-value child roots under a broad parent. If an
            # explicit parent and child are both supplied by tests/caller, keep both.
            if not self._explicit_roots and any(_is_parent(existing, resolved) for existing in out):
                continue
            seen.add(key)
            out.append(resolved)
        return out

    def _focused_default_roots(self) -> list[Path]:
        home = Path.home()
        env = os.environ
        roots = [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            home / "AppData" / "Roaming",
            home / "AppData" / "Local",
            Path(env.get("TEMP", str(home / "AppData" / "Local" / "Temp"))),
            Path(env.get("ProgramFiles", r"C:\Program Files")),
            Path(env.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
            Path(env.get("ProgramData", r"C:\ProgramData")),
            *self._drive_high_value_roots(),
        ]
        return roots

    def _drive_high_value_roots(self) -> list[Path]:
        names = (
            "Games",
            "Minecraft",
            ".minecraft",
            "ModrinthApp",
            "PrismLauncher",
            "MultiMC",
            "CurseForge",
            "ATLauncher",
            "GDLauncher",
            "Technic",
            "FTB",
            "SteamLibrary",
            "Steam",
            "Epic Games",
            "Riot Games",
            "Launchers",
        )
        roots: list[Path] = []
        for drive in self._fixed_drive_roots():
            for name in names:
                roots.append(drive / name)
            # If a secondary drive has a Users folder, include it. On C:\ this is
            # intentionally skipped because the user profile roots above are better.
            if str(drive).lower()[:2] != str(Path.home().anchor).lower()[:2]:
                roots.append(drive / "Users")
        return roots

    def _scan_root(self, root: Path) -> None:
        self.log("SCAN", f"Inventory root: {root}")
        stack = [root]
        visited = 0
        root_files_seen_before = self.stats.files_seen
        root_items_before = len(self._items)
        while stack:
            current = stack.pop()
            if visited >= self.max_folders_per_root:
                self._note(f"folder safety limit reached under {root}")
                self.log("WARN", f"Folder limit reached under {root}; continuing with next root")
                break
            visited += 1
            if visited % PROGRESS_EVERY_FOLDERS == 0:
                self.log(
                    "INDEX",
                    f"{root} | folders {visited} | files {self.stats.files_seen} | supported {len(self._items)}",
                )
            self.stats.scanned_folders += 1
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if self._skip_dir(entry):
                                    continue
                                stack.append(Path(entry.path))
                                continue
                            if entry.is_file(follow_symlinks=False):
                                self.stats.files_seen += 1
                                self._handle_file(Path(entry.path))
                                if self.max_files and len(self._items) >= self.max_files:
                                    return
                        except (OSError, PermissionError) as exc:
                            self._skip(f"{entry.path}: {exc}")
            except PermissionError as exc:
                self.stats.permission_denied += 1
                self._skip(f"{current}: {exc}")
            except OSError as exc:
                self._skip(f"{current}: {exc}")
        files_delta = self.stats.files_seen - root_files_seen_before
        items_delta = len(self._items) - root_items_before
        self.log("SCAN", f"Inventory root complete: {root} | files {files_delta} | supported {items_delta}")

    def _handle_file(self, path: Path) -> None:
        file_type = classify_file(path)
        if file_type == "UNKNOWN":
            return
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        key = str(resolved).lower()
        if key in self._seen_realpaths:
            self.stats.duplicate_realpaths += 1
            return
        self._seen_realpaths.add(key)
        try:
            stat = resolved.stat()
        except OSError as exc:
            self._skip(f"{resolved}: {exc}")
            return
        item = FileInventoryItem(
            path=resolved,
            file_name=resolved.name,
            extension=resolved.suffix.lower(),
            file_type=file_type,
            size_bytes=stat.st_size,
            created_time=dt.datetime.fromtimestamp(getattr(stat, "st_ctime", stat.st_mtime)).replace(microsecond=0),
            last_modified=dt.datetime.fromtimestamp(stat.st_mtime).replace(microsecond=0),
            folder_category=classify_folder(resolved),
            quick_hash=_quick_hash(resolved, stat.st_size, stat.st_mtime),
        )
        self._items.append(item)

    def _skip_dir(self, entry) -> bool:
        name = entry.name.lower()
        if name in SKIP_DIR_NAMES:
            self.stats.skipped_folders += 1
            return True
        try:
            if entry.is_symlink():
                self.stats.skipped_folders += 1
                return True
        except OSError:
            self.stats.skipped_folders += 1
            return True
        if not self._explicit_roots and _low_value_path(entry.path):
            self.stats.skipped_folders += 1
            return True
        return False

    def _fixed_drive_roots(self) -> list[Path]:
        if os.name != "nt":
            return [Path("/")]
        roots: list[Path] = []
        for letter in string.ascii_uppercase:
            root = Path(f"{letter}:\\")
            if root.exists() and self._drive_type(root) == DRIVE_FIXED:
                roots.append(root)
        return roots

    def _drive_type(self, root: Path) -> int:
        try:
            return int(ctypes.windll.kernel32.GetDriveTypeW(str(root)))
        except Exception:
            return DRIVE_FIXED

    def _skip(self, message: str) -> None:
        self.stats.skipped_folders += 1
        self.stats.errors_recovered += 1
        self._note(f"inventory skipped {message}")

    def _note(self, message: str) -> None:
        if len(self.stats.notes) < MAX_NOTES:
            self.stats.notes.append(message)


def _quick_hash(path: Path, size: int, mtime: float) -> str:
    digest = hashlib.sha256()
    digest.update(str(size).encode("ascii"))
    digest.update(str(int(mtime)).encode("ascii"))
    try:
        with path.open("rb") as fh:
            digest.update(fh.read(64 * 1024))
    except OSError:
        return ""
    return digest.hexdigest()


def _is_parent(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _env_flag(name: str) -> bool:
    value = os.environ.get(name, "")
    return value.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except ValueError:
        return default


def _low_value_path(path: str) -> bool:
    lower = path.lower()
    return any(fragment in lower for fragment in LOW_VALUE_PATH_FRAGMENTS)
