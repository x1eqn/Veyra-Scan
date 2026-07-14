from __future__ import annotations

import ctypes
import os
import re
import string
import subprocess
from pathlib import Path
from typing import Callable

from .exe_models import ExeDiscoveryStats


LogFn = Callable[[str, str], None]

DRIVE_FIXED = 3
MAX_FOLDERS_PER_ROOT = 600_000
MAX_DISCOVERY_NOTES = 80
SKIP_DIR_NAMES = {
    "$recycle.bin",
    "$windows.~bt",
    "$windows.~ws",
    "system volume information",
    "recovery",
}


class ExeDiscovery:
    def __init__(self, log: LogFn | None = None, roots: list[Path] | None = None, max_exes: int | None = None):
        self.log = log or (lambda _tag, _msg: None)
        self.roots = roots
        self.max_exes = max_exes
        self.stats = ExeDiscoveryStats()
        self._seen_realpaths: set[str] = set()
        self._found: list[Path] = []

    def discover(self) -> tuple[list[Path], ExeDiscoveryStats]:
        self.log("EXE-DISCOVERY", "Scanning fixed drives and user executable locations...")
        for root in self._candidate_roots():
            self._scan_root(root)
            if self.max_exes and len(self._found) >= self.max_exes:
                self._note("exe discovery stopped after configured limit")
                break
        if self.roots is None:
            for path in self._startup_registry_paths() + self._scheduled_task_paths() + self._running_process_paths():
                self._add_exe(path)
        self.stats.exe_found = len(self._found)
        return self._found, self.stats

    def _candidate_roots(self) -> list[Path]:
        roots: list[Path] = []
        if self.roots is not None:
            roots.extend(self.roots)
        else:
            roots.extend(self._fixed_drive_roots())
            home = Path.home()
            roots.extend(
                [
                    home,
                    home / "Downloads",
                    home / "Desktop",
                    home / "Documents",
                    home / "AppData" / "Roaming",
                    home / "AppData" / "Local",
                    Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
                    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
                    Path(os.environ.get("ProgramData", r"C:\ProgramData")),
                    Path(os.environ.get("TEMP", str(home / "AppData" / "Local" / "Temp"))),
                    Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming"))) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
                    Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
                ]
            )
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
            if any(_is_parent(existing, resolved) for existing in out):
                continue
            seen.add(key)
            out.append(resolved)
        return out

    def _scan_root(self, root: Path) -> None:
        self.log("EXE-DISCOVERY", f"Scanning: {root}")
        stack = [root]
        visited = 0
        while stack:
            current = stack.pop()
            if visited >= MAX_FOLDERS_PER_ROOT:
                self._note(f"folder safety limit reached under {root}")
                break
            visited += 1
            self.stats.scanned_folders += 1
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if not self._skip_dir(entry):
                                    stack.append(Path(entry.path))
                                continue
                            if entry.is_file(follow_symlinks=False) and entry.name.lower().endswith(".exe"):
                                self._add_exe(Path(entry.path))
                                if self.max_exes and len(self._found) >= self.max_exes:
                                    return
                        except (OSError, PermissionError) as exc:
                            self._skip(f"{entry.path}: {exc}")
            except (OSError, PermissionError) as exc:
                self._skip(f"{current}: {exc}")

    def _add_exe(self, path: Path) -> None:
        if self.max_exes and len(self._found) >= self.max_exes:
            return
        try:
            if not path.exists() or not path.is_file():
                return
            resolved = path.resolve()
        except (OSError, PermissionError):
            resolved = path
        key = str(resolved).lower()
        if key in self._seen_realpaths:
            self.stats.duplicate_realpaths += 1
            return
        self._seen_realpaths.add(key)
        self._found.append(resolved)
        if len(self._found) <= 50 or len(self._found) % 250 == 0:
            self.log("EXE-FOUND", str(resolved))

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

    def _startup_registry_paths(self) -> list[Path]:
        if os.name != "nt":
            return []
        try:
            import winreg
        except ImportError:
            return []
        out: list[Path] = []
        for hive, subkey in (
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ):
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for index in range(count):
                        _name, value, _kind = winreg.EnumValue(key, index)
                        out.extend(_extract_exe_paths(str(value)))
            except OSError:
                self._note("startup registry discovery unavailable")
        return out

    def _scheduled_task_paths(self) -> list[Path]:
        command = ["schtasks", "/Query", "/FO", "CSV", "/V"]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired):
            self._note("scheduled task discovery unavailable")
            return []
        if completed.returncode != 0:
            self._note("scheduled task discovery unavailable")
            return []
        return _extract_exe_paths(completed.stdout)

    def _running_process_paths(self) -> list[Path]:
        command = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-Process | ForEach-Object { try { $_.Path } catch {} }",
        ]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired):
            self._note("running process discovery unavailable")
            return []
        if completed.returncode != 0:
            self._note("running process discovery unavailable")
            return []
        return [Path(line.strip()) for line in completed.stdout.splitlines() if line.strip().lower().endswith(".exe")]

    def _skip(self, message: str) -> None:
        self.stats.skipped_folders += 1
        self.stats.errors_recovered += 1
        self._note(f"exe discovery skipped {message}")

    def _note(self, message: str) -> None:
        if len(self.stats.discovery_notes) < MAX_DISCOVERY_NOTES:
            self.stats.discovery_notes.append(message)


def _extract_exe_paths(text: str) -> list[Path]:
    out: list[Path] = []
    expanded = os.path.expandvars(text)
    patterns = [
        r'"([A-Za-z]:\\[^"]+?\.exe)"',
        r"([A-Za-z]:\\[^\s,;]+?\.exe)",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, expanded, flags=re.IGNORECASE):
            out.append(Path(match.strip().strip('"')))
    return out


def _is_parent(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False
