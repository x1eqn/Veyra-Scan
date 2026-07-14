from __future__ import annotations

import datetime as dt
import gzip
import os
import re
import zipfile

from .models import JarScanResult, LauncherLocation


PATTERN = re.compile(
    rb"auto[ _./\\-]*click(?:er|ing)?|click[ _./\\-]*assist|cps[ _./\\-]*(?:limit|counter|boost)"
    rb"|xray|x-ray|true[ _./\\-]*sight|wall[ _./\\-]*hack|see[ _./\\-]*through[ _./\\-]*wall"
    rb"|entity[ _./\\-]*radar|chest[ _./\\-]*tracker"
    rb"|auto[ _./\\-]*totem|totem[ _./\\-]*(?:pop|switch|swap)"
    rb"|mace[ _./\\-]*(?:swap(?:per|helper)?|switch)|swap[ _./\\-]*(?:helper|mace)",
    re.IGNORECASE,
)
MAX_LOGS = 600
MAX_LOG_BYTES = 24 * 1024 * 1024
MAX_JAR_BYTES = 96 * 1024 * 1024


class AutoClickerFinder:
    """Finds Xray/clicker and combat-helper traces in logs, mods and packs."""

    def scan(self, locations: list[LauncherLocation], jars: list[JarScanResult]) -> list[dict[str, object]]:
        findings = self._scan_logs(locations)
        findings.extend(self._scan_jars(self._all_mod_jars(locations, jars)))
        if os.environ.get("XIEN_CONTROL_SCAN_TEXTUREPACKS", "1") == "1":
            findings.extend(self._scan_resourcepacks(locations))
        unique = []
        seen = set()
        for item in findings:
            key = (str(item.get("source_type")), str(item.get("path")), str(item.get("evidence")))
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def _scan_resourcepacks(self, locations):
        findings = []
        for location in locations:
            root = location.mods_path.parent / "resourcepacks"
            if not root.is_dir():
                continue
            try:
                candidates = list(root.iterdir())[:500]
            except OSError:
                continue
            for pack in candidates:
                try:
                    if pack.is_dir():
                        files = pack.rglob("*")
                        for path in files:
                            if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                                continue
                            data = path.read_bytes()[:8 * 1024 * 1024]
                            match = PATTERN.search(path.name.encode() + b" " + data)
                            if match:
                                findings.append({"source_type": "resourcepack", "path": str(path), "pack": pack.name,
                                    "evidence": match.group().decode("ascii", errors="replace"),
                                    "message": "Xray/visibility, click-assist, Auto-Totem, or Mace-Swap helper text was found in a texture pack file."})
                                break
                    elif pack.is_file() and pack.suffix.lower() in {".zip", ".mcpack"}:
                        with zipfile.ZipFile(pack) as archive:
                            total = 0
                            for info in archive.infolist():
                                if info.is_dir() or info.file_size > 8 * 1024 * 1024 or total >= MAX_JAR_BYTES:
                                    continue
                                name = info.filename.encode("utf-8", errors="ignore")
                                with archive.open(info) as entry:
                                    data = entry.read(min(info.file_size, 8 * 1024 * 1024))
                                total += len(data)
                                match = PATTERN.search(name + b" " + data)
                                if match:
                                    findings.append({"source_type": "resourcepack", "path": str(pack), "pack": pack.name,
                                        "evidence": f"{info.filename}: {match.group().decode('ascii', errors='replace')}",
                                        "message": "Xray/visibility, click-assist, Auto-Totem, or Mace-Swap helper text was found inside a texture pack archive."})
                                    break
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    continue
        return findings

    def _all_mod_jars(self, locations, analyzed):
        results = list(analyzed)
        known = {str(item.path).lower() for item in analyzed}
        for location in locations:
            if not location.mods_path.is_dir():
                continue
            try:
                for path in location.mods_path.rglob("*.jar"):
                    key = str(path).lower()
                    if key in known or len(results) >= 5000:
                        continue
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    known.add(key)
                    results.append(JarScanResult(path=path, file_name=path.name, sha256="", size_bytes=stat.st_size,
                        last_modified=dt.datetime.fromtimestamp(stat.st_mtime), launcher_name=location.launcher_name,
                        instance_name=location.instance_name))
            except OSError:
                continue
        return results

    def _scan_logs(self, locations):
        findings = []
        checked = 0
        roots = {(location.mods_path.parent / "logs"): (location.launcher_name, location.instance_name) for location in locations}
        for root, instance in roots.items():
            if not root.is_dir():
                continue
            try:
                for path in root.rglob("*"):
                    if checked >= MAX_LOGS:
                        return findings
                    if not path.is_file() or not path.name.lower().endswith((".log", ".txt", ".log.gz", ".txt.gz")):
                        continue
                    checked += 1
                    try:
                        if path.stat().st_size > MAX_LOG_BYTES:
                            continue
                        opener = gzip.open if path.suffix.lower() == ".gz" else open
                        with opener(path, "rb") as handle:
                            data = handle.read(MAX_LOG_BYTES + 1)
                    except (OSError, EOFError, gzip.BadGzipFile):
                        continue
                    for number, line in enumerate(data.splitlines(), 1):
                        match = PATTERN.search(line)
                        if match:
                            findings.append({"source_type": "log", "path": str(path), "launcher": instance[0],
                                "instance": instance[1], "line": number, "evidence": line.decode("utf-8", errors="replace")[:300],
                                "matched": match.group().decode("ascii", errors="replace"),
                                "message": "Xray/visibility, AutoClicker, Auto-Totem, or Mace-Swap helper text was referenced while the instance was running or loading mods."})
                            if len(findings) >= 50:
                                return findings
            except OSError:
                continue
        return findings

    def _scan_jars(self, jars):
        findings = []
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
                        name_match = PATTERN.search(info.filename.encode("utf-8", errors="ignore"))
                        if name_match:
                            findings.append(self._jar_finding(jar, f"archive entry: {info.filename}", info.filename))
                            break
                        if info.is_dir() or info.file_size > 4 * 1024 * 1024 or total >= MAX_JAR_BYTES:
                            continue
                        with archive.open(info) as entry:
                            data = entry.read(min(info.file_size, 4 * 1024 * 1024))
                        total += len(data)
                        match = PATTERN.search(data)
                        if match:
                            findings.append(self._jar_finding(jar, f"content inside: {info.filename}", match.group().decode("ascii", errors="replace")))
                            break
            except (OSError, zipfile.BadZipFile, RuntimeError):
                continue
        return findings

    @staticmethod
    def _jar_finding(jar, evidence, matched):
        return {"source_type": "mod", "path": str(jar.path), "launcher": jar.launcher_name,
            "instance": jar.instance_name, "file": jar.file_name, "evidence": evidence, "matched": matched,
            "message": "Xray/visibility, AutoClicker, Auto-Totem, or Mace-Swap helper identity was found in mod metadata, a class path, or class content."}
