from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from .models import LauncherLocation
from .utils import env_path, is_jar_like


LogFn = Callable[[str, str], None]

SKIP_DIRS = {
    "$recycle.bin",
    ".cache",
    ".git",
    ".gradle",
    ".idea",
    ".m2",
    ".nuget",
    ".vscode",
    "__pycache__",
    "cache",
    "caches",
    "crash-reports",
    "libraries",
    "logs",
    "node_modules",
    "onedrive",
    "pictures",
    "screenshots",
    "videos",
}

MINECRAFT_CONTEXT_TOKENS = {
    ".minecraft",
    "minecraft",
    "mods",
    "modpack",
    "modpacks",
    "instances",
    "instance",
    "launcher",
    "launchers",
    "clients",
    "client",
    "fabric",
    "forge",
    "quilt",
    "curseforge",
    "modrinth",
    "modrinthapp",
    "prismlauncher",
    "prism",
    "multimc",
    "technic",
    "ftb",
    "ftbapp",
    "atlauncher",
    "gdlauncher",
    "gdlauncher_next",
    "lunarclient",
    "badlion",
    "feather",
    "tlauncher",
    "legacylauncher",
    "sklauncher",
    "hmcl",
    "pojavlauncher",
}

GENERIC_CONTEXT_NAMES = {
    "mods",
    "modpack",
    "modpacks",
    "instances",
    "instance",
    "minecraft",
    ".minecraft",
    "launcher",
    "launchers",
    "clients",
    "client",
    "fabric",
    "forge",
    "quilt",
    "curseforge",
    "modrinth",
    "prism",
    "multimc",
    "technic",
    "ftb",
    "atlauncher",
    "gdlauncher",
}


class LauncherDiscovery:
    def __init__(self, log: LogFn | None = None):
        self.home = Path.home()
        self.appdata = env_path("APPDATA", self.home / "AppData" / "Roaming")
        self.local = env_path("LOCALAPPDATA", self.home / "AppData" / "Local")
        self.log = log or (lambda _tag, _msg: None)
        self.locations: list[LauncherLocation] = []
        self.version_jars: list[Path] = []
        self.errors: list[str] = []
        self._seen_locations: set[str] = set()
        self._seen_versions: set[str] = set()

    def discover(self) -> tuple[list[LauncherLocation], list[Path], list[str]]:
        self.log("DISCOVERY", "Searching Minecraft launcher folders...")
        self._official_minecraft()
        self._lunar()
        self._badlion()
        self._feather()
        self._modrinth_and_essential()
        self._prism()
        self._multimc()
        self._curseforge()
        self._atlauncher()
        self._gdlauncher()
        self._technic()
        self._ftb()
        self._tlauncher()
        self._legacy()
        self._sklauncher()
        self._hmcl()
        self._pojav_backups()
        self._generic_user_discovery()
        return self.locations, self.version_jars, self.errors

    def _official_minecraft(self) -> None:
        root = self.appdata / ".minecraft"
        self._add_mods("Official Minecraft", "default", root / "mods", "known official mods path")
        for reference_root in (
            root / "versions",
            root / "libraries",
            root / "resourcepacks",
            root / "shaderpacks",
        ):
            self._collect_reference_jars(reference_root, max_depth=12, max_entries=2500)

    def _lunar(self) -> None:
        self._scan_roots(
            "Lunar Client",
            (
                self.home / ".lunarclient",
                self.home / ".lunarclient" / "offline",
                self.home / ".lunarclient" / "profiles",
                self.appdata / ".lunarclient",
                self.local / "Programs" / "lunarclient",
            ),
            max_depth=7,
        )

    def _badlion(self) -> None:
        self._scan_roots(
            "Badlion Client",
            (
                self.appdata / "Badlion Client",
                self.local / "Badlion Client",
                self.home / "AppData" / "Roaming" / "Badlion Client",
            ),
            max_depth=7,
        )

    def _feather(self) -> None:
        self._scan_roots(
            "Feather Client",
            (
                self.appdata / ".feather",
                self.appdata / "Feather Client",
                self.local / "Feather Client",
                self.home / ".feather",
            ),
            max_depth=7,
        )

    def _modrinth_and_essential(self) -> None:
        self._scan_roots(
            "Modrinth / Essential",
            (
                self.appdata / ".minecraft" / "essential_mod",
                self.appdata / ".minecraft" / "config",
                self.appdata / ".minecraft" / "mods",
                self.appdata / "ModrinthApp",
                self.local / "ModrinthApp",
                self.appdata / "com.modrinth.theseus",
                self.local / "com.modrinth.theseus",
            ),
            max_depth=8,
        )

    def _prism(self) -> None:
        self._scan_roots(
            "Prism Launcher",
            (
                self.appdata / "PrismLauncher",
                self.appdata / "PrismLauncher" / "instances",
                self.local / "PrismLauncher",
                self.home / "PrismLauncher",
                self.home / "Documents" / "PrismLauncher",
            ),
            max_depth=8,
        )

    def _multimc(self) -> None:
        self._scan_roots(
            "MultiMC",
            (
                self.appdata / "MultiMC",
                self.local / "MultiMC",
                self.home / "MultiMC",
                self.home / "multimc",
                self.home / "Documents" / "MultiMC",
                self.home / "Desktop" / "MultiMC",
                self.home / "Downloads" / "MultiMC",
            ),
            max_depth=8,
        )

    def _curseforge(self) -> None:
        self._scan_roots(
            "CurseForge",
            (
                self.home / "curseforge",
                self.home / "CurseForge",
                self.home / "Documents" / "CurseForge",
                self.home / "Twitch" / "Minecraft",
                self.appdata / "CurseForge",
                self.local / "CurseForge",
            ),
            max_depth=8,
        )

    def _atlauncher(self) -> None:
        self._scan_roots(
            "ATLauncher",
            (
                self.appdata / "ATLauncher",
                self.local / "ATLauncher",
                self.home / "ATLauncher",
                self.home / "Documents" / "ATLauncher",
            ),
            max_depth=8,
        )

    def _gdlauncher(self) -> None:
        self._scan_roots(
            "GDLauncher",
            (
                self.appdata / "gdlauncher_next",
                self.local / "gdlauncher_next",
                self.appdata / "GDLauncher",
                self.local / "GDLauncher",
                self.home / "GDLauncher",
                self.home / "Documents" / "GDLauncher",
            ),
            max_depth=8,
        )

    def _technic(self) -> None:
        self._scan_roots(
            "Technic Launcher",
            (
                self.appdata / ".technic",
                self.appdata / ".technic" / "modpacks",
                self.home / ".technic",
                self.home / "AppData" / "Roaming" / ".technic",
            ),
            max_depth=8,
        )

    def _ftb(self) -> None:
        self._scan_roots(
            "FTB App",
            (
                self.local / ".ftba",
                self.appdata / ".ftba",
                self.home / ".ftba",
                self.home / "Documents" / "FTB",
                self.home / "FTB",
                self.appdata / "FTBApp",
                self.local / "FTBApp",
            ),
            max_depth=8,
        )

    def _tlauncher(self) -> None:
        self._scan_roots(
            "TLauncher",
            (
                self.appdata / ".minecraft",
                self.appdata / ".tlauncher",
                self.appdata / "TLauncher",
                self.home / ".tlauncher",
                self.home / "AppData" / "Roaming" / ".tlauncher",
            ),
            max_depth=7,
        )

    def _legacy(self) -> None:
        self._scan_roots(
            "Legacy Launcher",
            (
                self.appdata / ".minecraft",
                self.appdata / ".legacylauncher",
                self.home / ".legacylauncher",
            ),
            max_depth=7,
        )

    def _sklauncher(self) -> None:
        self._scan_roots(
            "SKLauncher",
            (
                self.appdata / ".sklauncher",
                self.appdata / "SKlauncher",
                self.home / ".sklauncher",
            ),
            max_depth=7,
        )

    def _hmcl(self) -> None:
        self._scan_roots(
            "HMCL",
            (
                self.appdata / ".hmcl",
                self.home / ".hmcl",
                self.home / "Documents" / "HMCL",
                self.home / "Downloads" / "HMCL",
            ),
            max_depth=7,
        )

    def _pojav_backups(self) -> None:
        self._scan_roots(
            "PojavLauncher Backup",
            (
                self.home / "Downloads" / "PojavLauncher",
                self.home / "Documents" / "PojavLauncher",
                self.home / "Desktop" / "PojavLauncher",
            ),
            max_depth=7,
        )

    def _generic_user_discovery(self) -> None:
        roots = [
            self.home / ".minecraft",
            self.home / "Documents",
            self.home / "Desktop",
            self.home / "Downloads",
        ]
        try:
            for child in self.home.iterdir():
                if not child.is_dir():
                    continue
                if self._is_context_name(child.name):
                    roots.append(child)
        except OSError as exc:
            self.errors.append(f"Generic user search skipped home listing: {exc}")

        for root in roots:
            self._find_mod_dirs("Generic Minecraft", root, max_depth=5, max_entries=7000, source="bounded user search")

    def _scan_roots(self, launcher: str, roots: tuple[Path, ...], max_depth: int) -> None:
        for root in roots:
            if root.name.lower() == "mods":
                self._add_mods(launcher, self._instance_name(root), root, "known launcher path")
            self._find_mod_dirs(launcher, root, max_depth=max_depth, source="recursive launcher search")

    def _find_mod_dirs(
        self,
        launcher: str,
        root: Path,
        max_depth: int,
        source: str,
        max_entries: int = 9000,
    ) -> None:
        if not root.exists() or not root.is_dir():
            return
        try:
            root = root.resolve()
        except OSError:
            root = root.expanduser()
        stack: list[tuple[Path, int]] = [(root, 0)]
        visited = 0
        while stack and visited < max_entries:
            current, depth = stack.pop()
            visited += 1
            try:
                name_lower = current.name.lower()
                if depth > 0 and name_lower in SKIP_DIRS:
                    continue
                if name_lower == "mods" and self._looks_like_minecraft_context(current):
                    self._add_mods(launcher, self._instance_name(current), current, source)
                    continue
                if depth >= max_depth:
                    continue
                with os.scandir(current) as entries:
                    for entry in entries:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                        entry_name = entry.name.lower()
                        if entry_name in SKIP_DIRS:
                            continue
                        if source == "bounded user search" and depth == 0 and not self._is_context_name(entry.name):
                            if current not in {self.home / "Documents", self.home / "Desktop", self.home / "Downloads"}:
                                continue
                        stack.append((Path(entry.path), depth + 1))
            except (OSError, PermissionError) as exc:
                if source != "bounded user search":
                    self.errors.append(f"{launcher}: skipped {current}: {exc}")

    def _looks_like_minecraft_context(self, mods_path: Path) -> bool:
        try:
            has_jar = any(is_jar_like(child) for child in mods_path.iterdir() if child.is_file())
        except OSError:
            has_jar = False
        parts = {part.lower() for part in mods_path.parts}
        return has_jar or bool(parts.intersection(MINECRAFT_CONTEXT_TOKENS))

    def _add_mods(self, launcher: str, instance: str, path: Path, source: str) -> None:
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            resolved = path.expanduser()
        key = str(resolved).lower()
        if key in self._seen_locations or not resolved.exists() or not resolved.is_dir():
            return
        self._seen_locations.add(key)
        location = LauncherLocation(launcher, instance or "<unknown>", resolved, source)
        self.locations.append(location)
        self.log("FOUND", f"{launcher} mods folder: {resolved}")

    def _collect_reference_jars(self, root: Path, max_depth: int, max_entries: int) -> None:
        if not root.exists() or not root.is_dir():
            return
        stack: list[tuple[Path, int]] = [(root, 0)]
        visited = 0
        while stack and visited < max_entries:
            current, depth = stack.pop()
            visited += 1
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        path = Path(entry.path)
                        if entry.is_file(follow_symlinks=False) and is_jar_like(path):
                            self._add_reference_jar(path)
                        elif entry.is_dir(follow_symlinks=False) and depth < max_depth:
                            if entry.name.lower() not in SKIP_DIRS:
                                stack.append((path, depth + 1))
            except (OSError, PermissionError) as exc:
                self.errors.append(f"Reference jars skipped at {current}: {exc}")

    def _add_reference_jar(self, path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        key = str(resolved).lower()
        if key in self._seen_versions:
            return
        self._seen_versions.add(key)
        self.version_jars.append(resolved)

    def _is_context_name(self, name: str) -> bool:
        normalized = name.lower().replace(" ", "").replace("-", "").replace("_", "")
        direct = name.lower()
        if direct in GENERIC_CONTEXT_NAMES:
            return True
        return any(token.replace("_", "") in normalized for token in GENERIC_CONTEXT_NAMES)

    def _instance_name(self, mods_path: Path) -> str:
        parent = mods_path.parent
        if parent.name.lower() in {".minecraft", "minecraft"} and parent.parent.name:
            return parent.parent.name
        if parent.name:
            return parent.name
        return mods_path.name
