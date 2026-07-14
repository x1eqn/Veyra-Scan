from __future__ import annotations

import ctypes
import os
import string
from pathlib import Path
from typing import Callable

from .archive_identifier import identify_java_archive
from .executable_scanner import looks_suspicious_executable_path
from .launcher_discovery import SKIP_DIRS
from .models import LauncherLocation
from .utils import is_jar_like


LogFn = Callable[[str, str], None]

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3

MAX_SYSTEM_ENTRIES_PER_DRIVE = 350_000
MAX_SYSTEM_JARS = 12_000
MAX_EXE_CANDIDATES = 500
MAX_DISCOVERY_ERRORS = 60

SYSTEM_SKIP_DIRS = SKIP_DIRS | {
    "$windows.~bt",
    "$windows.~ws",
    "appdata\\local\\temp",
    "msocache",
    "pagefile.sys",
    "perflogs",
    "programdata\\microsoft\\windows defender",
    "recovery",
    "swapfile.sys",
    "system volume information",
    "windows",
    "winsxs",
}


class SystemDiscovery:
    def __init__(self, log: LogFn | None = None):
        self.log = log or (lambda _tag, _msg: None)
        self.jar_targets: list[tuple[Path, LauncherLocation]] = []
        self.exe_candidates: list[Path] = []
        self.errors: list[str] = []
        self._seen_jars: set[str] = set()
        self._seen_exes: set[str] = set()

    def discover(self) -> tuple[list[tuple[Path, LauncherLocation]], list[Path], list[str]]:
        self.log("SYSTEM", "Searching accessible drives for jar files...")
        for root in self._drive_roots():
            self.log("SYSTEM", f"Wide scan root: {root}")
            self._scan_root(root)
            if len(self.jar_targets) >= MAX_SYSTEM_JARS:
                self._add_error("Wide jar search stopped after reaching the safety limit.")
                break
        return self.jar_targets, self.exe_candidates, self.errors

    def _scan_root(self, root: Path) -> None:
        stack: list[Path] = [root]
        visited = 0
        while stack and visited < MAX_SYSTEM_ENTRIES_PER_DRIVE:
            current = stack.pop()
            visited += 1
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            path = Path(entry.path)
                            if entry.is_dir(follow_symlinks=False):
                                if not self._should_skip_dir(path):
                                    stack.append(path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            self._handle_file(path)
                        except (OSError, PermissionError) as exc:
                            self._add_error(f"Wide scan skipped {entry.path}: {exc}")
            except (OSError, PermissionError) as exc:
                self._add_error(f"Wide scan skipped {current}: {exc}")
        if visited >= MAX_SYSTEM_ENTRIES_PER_DRIVE:
            self._add_error(f"Wide scan stopped early at {root} after {visited} folders.")

    def _handle_file(self, path: Path) -> None:
        ok, _archive_type = identify_java_archive(path, broad=False) if is_jar_like(path) else (False, "")
        if ok:
            self._add_jar(path)
            return
        if path.suffix.lower() == ".exe" and len(self.exe_candidates) < MAX_EXE_CANDIDATES:
            if looks_suspicious_executable_path(path):
                self._add_exe(path)

    def _add_jar(self, path: Path) -> None:
        if len(self.jar_targets) >= MAX_SYSTEM_JARS:
            return
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        key = str(resolved).lower()
        if key in self._seen_jars:
            return
        self._seen_jars.add(key)
        location = LauncherLocation(
            launcher_name="System-wide Jar Search",
            instance_name=self._instance_name(resolved),
            mods_path=resolved.parent,
            source="wide computer search",
            location_type="jar_file",
        )
        self.jar_targets.append((resolved, location))

    def _add_exe(self, path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        key = str(resolved).lower()
        if key in self._seen_exes:
            return
        self._seen_exes.add(key)
        self.exe_candidates.append(resolved)

    def _drive_roots(self) -> list[Path]:
        if os.name != "nt":
            return [Path("/")]
        roots: list[Path] = []
        for letter in string.ascii_uppercase:
            root = Path(f"{letter}:\\")
            if not root.exists():
                continue
            if self._drive_type(root) in {DRIVE_FIXED, DRIVE_REMOVABLE}:
                roots.append(root)
        return roots

    def _drive_type(self, root: Path) -> int:
        try:
            return int(ctypes.windll.kernel32.GetDriveTypeW(str(root)))
        except Exception:
            return DRIVE_FIXED

    def _should_skip_dir(self, path: Path) -> bool:
        name = path.name.lower()
        if name in SYSTEM_SKIP_DIRS:
            return True
        lowered = str(path).lower()
        return any(skip in lowered for skip in SYSTEM_SKIP_DIRS if "\\" in skip)

    def _instance_name(self, jar_path: Path) -> str:
        for parent in jar_path.parents:
            if parent.name.lower() == "mods":
                owner = parent.parent.name
                return owner or "mods"
        return jar_path.parent.name or jar_path.anchor or "<unknown>"

    def _add_error(self, message: str) -> None:
        if len(self.errors) < MAX_DISCOVERY_ERRORS:
            self.errors.append(message)
