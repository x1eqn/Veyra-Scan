from __future__ import annotations

import gzip
import re
import zipfile
import datetime as dt
from pathlib import Path

from .models import JarScanResult, LauncherLocation


PATTERN = re.compile(rb"mouse[ _./\\-]*tweaks|yalter[./\\]+mousetweaks|mousetweaks[._-]*(?:cfg|json|toml)|modmenu\.mousetweaks", re.IGNORECASE)
MAX_LOGS = 600
MAX_LOG_BYTES = 24 * 1024 * 1024
MAX_JAR_BYTES = 96 * 1024 * 1024
MAX_CONFIG_FILES = 400


class MouseTweaksFinder:
    """Finds MouseTweaks traces in discovered instance logs and mod archives."""

    def scan(self, locations: list[LauncherLocation], jars: list[JarScanResult]) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        findings.extend(self._scan_logs(locations))
        findings.extend(self._scan_configs(locations))
        findings.extend(self._scan_jars(self._all_mod_jars(locations, jars)))
        unique: list[dict[str, object]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in findings:
            key = (str(item.get("source_type")), str(item.get("path")), str(item.get("evidence")))
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def _all_mod_jars(self, locations: list[LauncherLocation], analyzed: list[JarScanResult]) -> list[JarScanResult]:
        results = list(analyzed)
        known = {str(item.path).lower() for item in analyzed}
        for location in locations:
            if not location.mods_path.is_dir():
                continue
            try:
                candidates = (path for path in location.mods_path.rglob("*") if _is_mod_archive(path))
                for path in candidates:
                    key = str(path).lower()
                    if key in known or len(results) >= 5000:
                        continue
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    known.add(key)
                    results.append(JarScanResult(
                        path=path,
                        file_name=path.name,
                        sha256="",
                        size_bytes=stat.st_size,
                        last_modified=dt.datetime.fromtimestamp(stat.st_mtime),
                        launcher_name=location.launcher_name,
                        instance_name=location.instance_name,
                    ))
            except OSError:
                continue
        return results

    def _scan_logs(self, locations: list[LauncherLocation]) -> list[dict[str, object]]:
        roots: dict[Path, tuple[str, str]] = {}
        for location in locations:
            instance_root = location.mods_path.parent
            roots[instance_root / "logs"] = (location.launcher_name, location.instance_name)
        findings: list[dict[str, object]] = []
        checked = 0
        for root, instance in roots.items():
            if not root.is_dir():
                continue
            try:
                candidates = root.rglob("*")
                for path in candidates:
                    if checked >= MAX_LOGS:
                        return findings
                    if not path.is_file() or not _is_log(path):
                        continue
                    checked += 1
                    findings.extend(self._read_log(path, *instance))
            except OSError:
                continue
        return findings

    def _scan_configs(self, locations: list[LauncherLocation]) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        checked = 0
        for location in locations:
            root = location.mods_path.parent / "config"
            if not root.is_dir():
                continue
            try:
                for path in root.rglob("*"):
                    if checked >= MAX_CONFIG_FILES:
                        return findings
                    if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                        continue
                    checked += 1
                    try:
                        data = path.read_bytes()[: 2 * 1024 * 1024]
                    except OSError:
                        continue
                    match = PATTERN.search(path.name.encode("utf-8", errors="ignore") + b" " + data)
                    if match:
                        findings.append({
                            "source_type": "config",
                            "path": str(path),
                            "launcher": location.launcher_name,
                            "instance": location.instance_name,
                            "evidence": match.group().decode("ascii", errors="replace"),
                            "matched": match.group().decode("ascii", errors="replace"),
                            "confidence": "high" if "mousetweaks" in path.name.lower() else "medium",
                            "message": "A MouseTweaks configuration or identifier was found in the Minecraft instance config directory.",
                        })
            except OSError:
                continue
        return findings

    def _read_log(self, path: Path, launcher: str, instance: str) -> list[dict[str, object]]:
        try:
            if path.stat().st_size > MAX_LOG_BYTES:
                return []
            opener = gzip.open if path.suffix.lower() == ".gz" else open
            with opener(path, "rb") as handle:
                data = handle.read(MAX_LOG_BYTES + 1)
        except (OSError, EOFError, gzip.BadGzipFile):
            return []
        findings: list[dict[str, object]] = []
        for line_number, line in enumerate(data.splitlines(), 1):
            match = PATTERN.search(line)
            if not match:
                continue
            context = line.decode("utf-8", errors="replace").strip()
            findings.append({
                "source_type": "log",
                "path": str(path),
                "launcher": launcher,
                "instance": instance,
                "line": line_number,
                "evidence": context[:300],
                "message": "MouseTweaks was referenced while the Minecraft instance was running or loading mods.",
            })
            if len(findings) >= 30:
                break
        return findings

    def _scan_jars(self, jars: list[JarScanResult]) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        for jar in jars:
            direct = " ".join((jar.file_name, jar.mod_id, jar.mod_name)).encode("utf-8", errors="ignore")
            match = PATTERN.search(direct)
            if match:
                findings.append(self._jar_finding(jar, "file name or mod metadata", match.group().decode("ascii", errors="replace")))
                continue
            try:
                with zipfile.ZipFile(jar.path) as archive:
                    total = 0
                    for info in archive.infolist():
                        name_bytes = info.filename.encode("utf-8", errors="ignore")
                        name_match = PATTERN.search(name_bytes)
                        if name_match:
                            findings.append(self._jar_finding(jar, f"archive entry: {info.filename}", name_match.group().decode("ascii", errors="replace")))
                            break
                        if info.is_dir() or info.file_size > 4 * 1024 * 1024 or total >= MAX_JAR_BYTES:
                            continue
                        with archive.open(info) as entry:
                            data = entry.read(min(info.file_size, 4 * 1024 * 1024))
                        total += len(data)
                        content_match = PATTERN.search(data)
                        if content_match:
                            findings.append(self._jar_finding(jar, f"content inside: {info.filename}", content_match.group().decode("ascii", errors="replace")))
                            break
            except (OSError, zipfile.BadZipFile, RuntimeError):
                continue
        return findings

    @staticmethod
    def _jar_finding(jar: JarScanResult, evidence: str, matched: str) -> dict[str, object]:
        return {
            "source_type": "mod",
            "path": str(jar.path),
            "launcher": jar.launcher_name,
            "instance": jar.instance_name,
            "file": jar.file_name,
            "evidence": evidence,
            "matched": matched,
            "message": "MouseTweaks identity was found in the mod file, metadata, class name, or class content.",
        }


def _is_log(path: Path) -> bool:
    lower = path.name.lower()
    return lower.endswith((".log", ".txt", ".log.gz", ".txt.gz"))


def _is_mod_archive(path: Path) -> bool:
    lower = path.name.lower()
    return path.is_file() and lower.endswith((".jar", ".jar.disabled", ".jar.bak", ".jar.old", ".jar.tmp"))
