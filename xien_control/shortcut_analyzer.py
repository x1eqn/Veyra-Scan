from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .confidence import assign_confidence
from .exe_rules import classify_folder
from .priority import assign_priority
from .static_models import FileInventoryItem, StaticAnalysisResult
from .utils import sha256_file


class ShortcutAnalyzer:
    def analyze(self, item: FileInventoryItem) -> StaticAnalysisResult:
        result = StaticAnalysisResult(
            path=item.path,
            file_name=item.file_name,
            file_type=item.file_type,
            size_bytes=item.size_bytes,
            last_modified=item.last_modified,
            folder_category=item.folder_category,
        )
        try:
            result.sha256 = sha256_file(item.path)
        except OSError:
            result.sha256 = ""
        target = _read_url_target(item.path) if item.file_type == "SHORTCUT_URL" else _read_lnk_target(item.path)
        if not target:
            target = _fallback_path_string(item.path)
        result.target_path = target
        score = 0
        reasons: list[str] = []
        if not target:
            score += 12
            reasons.append("shortcut target could not be resolved")
        else:
            result.evidence.append(f"target: {target}")
            target_category = classify_folder(Path(os.path.expandvars(target)))
            if target.lower().endswith((".exe", ".dll", ".scr", ".jar", ".bat", ".cmd", ".ps1")):
                score += 18
                reasons.append("shortcut points to application/script target")
            if target_category in {"APPDATA_LOCAL", "APPDATA_ROAMING", "TEMP", "UNKNOWN_USER_FOLDER"}:
                score += 22
                reasons.append("shortcut points to user-writable location")
            if item.folder_category == "STARTUP":
                score += 25
                reasons.append("startup shortcut")
        result.risk_score = min(100, score)
        result.verdict = _verdict(score)
        result.reasons = reasons or ["shortcut has no strong static review signals"]
        assign_confidence(result, sources=2 if target else 1)
        assign_priority(result, linked_from_startup=item.folder_category == "STARTUP")
        return result


def _read_url_target(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"^URL=(.+)$", text, flags=re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else ""


def _read_lnk_target(path: Path) -> str:
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($args[0]); $s.TargetPath",
        str(path),
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _fallback_path_string(path: Path) -> str:
    try:
        data = path.read_bytes()[:64 * 1024]
    except OSError:
        return ""
    text = data.decode("utf-16le", errors="ignore") + "\n" + data.decode("utf-8", errors="ignore")
    match = re.search(r"([A-Za-z]:\\[^'\"\x00\r\n<>|]+?\.(?:exe|dll|scr|jar|bat|cmd|ps1))", text, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _verdict(score: int) -> str:
    if score >= 90:
        return "CRITICAL_REVIEW"
    if score >= 70:
        return "HIGH_REVIEW"
    if score >= 45:
        return "REVIEW"
    if score >= 20:
        return "LOW_SIGNAL"
    return "CLEAN"
