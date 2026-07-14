from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .client_names import find_client_name_matches
from .models import LauncherLocation


JAR_NAME_RE = re.compile(r"(?i)([A-Za-z0-9][A-Za-z0-9_.+@-]{2,180}\.jar(?:\.disabled)?)")
ARCHIVE_SUFFIXES = (".jar", ".jar.disabled", ".jar.bak", ".jar.old")
TRACE_FILE_NAMES = {
    "instance.cfg", "profile.json", "minecraftinstance.json", "manifest.json",
    "modrinth.index.json", "mmc-pack.json", "launcher_profiles.json",
}
RESTRICTED_TRACE_TOKENS = {
    "freecam", "freelook", "mousetweaks", "autoclicker", "triggerbot",
    "killaura", "xray", "wallhack", "autototem", "maceswap", "swaphelper",
}


class DeletedModTraceFinder:
    """Find historical JAR references that are absent from the current mods set.

    Findings are traces, not proof that a mod is currently active. The scanner
    intentionally limits itself to Minecraft instance logs/config/metadata and
    does not inspect account data or unrelated user documents.
    """

    def scan(self, locations: Iterable[LauncherLocation]) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        seen: set[tuple[str, str, str]] = set()
        for location in locations:
            mods_path = Path(location.mods_path)
            instance_root = mods_path.parent if mods_path.name.lower() == "mods" else mods_path
            installed = self._installed_names(mods_path)
            historical_names: set[str] = set()

            for path, source_type in self._trace_files(instance_root):
                for jar_name, line_number, evidence in self._jar_references(path):
                    normalized = jar_name.lower()
                    if self._is_installed(normalized, installed):
                        continue
                    historical_names.add(self._base_mod_token(normalized))
                    key = (source_type, str(path).lower(), normalized)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "source_type": source_type,
                        "path": str(path),
                        "line": line_number,
                        "mod_name": jar_name,
                        "evidence": evidence,
                        "confidence": "high" if source_type == "log" else "medium",
                        "message": "A historical Minecraft instance record references a JAR that is not present in the current mods folder.",
                        "launcher": location.launcher_name,
                        "instance": location.instance_name,
                    })

            config_root = instance_root / "config"
            if config_root.is_dir():
                for path in self._limited_files(config_root, 300):
                    token = self._base_mod_token(path.stem.lower())
                    if not token or self._is_installed(token, installed):
                        continue
                    compact = re.sub(r"[^a-z0-9]", "", token)
                    security_related = any(value in compact for value in RESTRICTED_TRACE_TOKENS) or bool(find_client_name_matches([path.name]))
                    corroborated = any(token in old or old in token for old in historical_names if len(old) >= 4)
                    if not security_related and not corroborated:
                        continue
                    key = ("config", str(path).lower(), token)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "source_type": "config",
                        "path": str(path),
                        "line": 0,
                        "mod_name": path.stem,
                        "evidence": path.name,
                        "confidence": "medium" if corroborated else "low",
                        "message": "A leftover mod configuration exists without a matching installed JAR.",
                        "launcher": location.launcher_name,
                        "instance": location.instance_name,
                    })
        return findings[:250]

    def _trace_files(self, instance_root: Path) -> list[tuple[Path, str]]:
        output: list[tuple[Path, str]] = []
        log_roots = [instance_root / "logs", instance_root / ".minecraft" / "logs"]
        for root in log_roots:
            if not root.is_dir():
                continue
            candidates = sorted(
                (path for path in root.glob("*.log*") if path.is_file()),
                key=lambda path: path.stat().st_mtime if path.exists() else 0,
                reverse=True,
            )[:20]
            output.extend((path, "log") for path in candidates)
        metadata_roots = [instance_root, instance_root / ".minecraft"]
        for root in metadata_roots:
            if not root.is_dir():
                continue
            for name in TRACE_FILE_NAMES:
                path = root / name
                if path.is_file():
                    output.append((path, "launcher_metadata"))
        return list(dict.fromkeys(output))[:40]

    def _jar_references(self, path: Path) -> list[tuple[str, int, str]]:
        try:
            if path.stat().st_size > 24 * 1024 * 1024:
                return []
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        output: list[tuple[str, int, str]] = []
        for number, line in enumerate(text.splitlines(), 1):
            for match in JAR_NAME_RE.finditer(line):
                output.append((match.group(1), number, line.strip()[:240]))
                if len(output) >= 300:
                    return output
        return output

    @staticmethod
    def _installed_names(mods_path: Path) -> set[str]:
        if not mods_path.is_dir():
            return set()
        return {path.name.lower() for path in mods_path.iterdir() if path.is_file() and path.name.lower().endswith(ARCHIVE_SUFFIXES)}

    @staticmethod
    def _base_mod_token(value: str) -> str:
        name = Path(value).name.lower()
        name = re.sub(r"\.jar(?:\.(?:disabled|bak|old))?$", "", name)
        name = re.sub(r"(?:[-_+]?(?:fabric|forge|quilt|neoforge))?(?:[-_+]?(?:mc)?\d+(?:\.\d+){1,3}.*)?$", "", name)
        return re.sub(r"[^a-z0-9_-]+", "", name).strip("-_")

    @classmethod
    def _is_installed(cls, value: str, installed: set[str]) -> bool:
        token = cls._base_mod_token(value)
        return value in installed or any(cls._base_mod_token(name) == token for name in installed if token)

    @staticmethod
    def _limited_files(root: Path, limit: int) -> list[Path]:
        output: list[Path] = []
        try:
            for path in root.rglob("*"):
                if path.is_file():
                    output.append(path)
                    if len(output) >= limit:
                        break
        except OSError:
            pass
        return output
