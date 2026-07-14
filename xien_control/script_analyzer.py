from __future__ import annotations

import base64
import re

from .confidence import assign_confidence
from .priority import assign_priority
from .static_models import FileInventoryItem, StaticAnalysisResult
from .utils import sha256_file


MAX_SCRIPT_BYTES = 512 * 1024


class ScriptAnalyzer:
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
            raw = item.path.read_bytes()[:MAX_SCRIPT_BYTES]
        except OSError as exc:
            result.error = str(exc)
            result.verdict = "REVIEW"
            result.risk_score = 45
            result.reasons.append("script could not be fully read")
            assign_confidence(result, sources=1, partial=True)
            assign_priority(result)
            return result
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        result.evidence.append(f"line count: {len(lines)}")
        exe_paths = _extract_paths(text, (".exe", ".dll", ".scr", ".jar", ".zip"))
        result.referenced_paths = exe_paths[:10]
        urls = re.findall(r"https?://[^\s'\"<>]+", text, flags=re.IGNORECASE)
        command_hits = _command_density(lines)
        encoded_lines = [line for line in lines if _encoded_like(line)]
        score = 0
        reasons: list[str] = []
        if exe_paths:
            score += 22
            reasons.append("script references application files")
            result.evidence.append("referenced path: " + exe_paths[0])
        if urls:
            score += 8
            result.evidence.append("url-like string: " + urls[0][:100])
        if command_hits >= 4:
            score += 12
            reasons.append("high command density")
        if encoded_lines:
            score += 18
            reasons.append("encoded-looking long script line")
            result.evidence.append("encoded-looking long line")
        if item.folder_category in {"STARTUP", "APPDATA_LOCAL", "APPDATA_ROAMING", "TEMP"}:
            score += 18
            reasons.append(f"script in {item.folder_category}")
        elif item.folder_category in {"USER_DOWNLOADS", "USER_DESKTOP"}:
            score += 8
        result.risk_score = min(100, score)
        result.verdict = _verdict(score)
        result.reasons = reasons or ["script has no strong static review signals"]
        assign_confidence(result, sources=3 if exe_paths or encoded_lines else 2)
        assign_priority(result)
        return result


def _extract_paths(text: str, extensions: tuple[str, ...]) -> list[str]:
    pattern = r"([A-Za-z]:\\[^'\"\r\n<>|]+?(?:" + "|".join(re.escape(ext) for ext in extensions) + r"))"
    out = []
    seen = set()
    for match in re.findall(pattern, text, flags=re.IGNORECASE):
        clean = match.strip()
        key = clean.lower()
        if key not in seen:
            seen.add(key)
            out.append(clean)
    return out


def _command_density(lines: list[str]) -> int:
    commands = ("powershell", "cmd", "start", "schtasks", "reg ", "curl", "wget", "invoke-webrequest", "wscript", "cscript")
    return sum(1 for line in lines if any(command in line.lower() for command in commands))


def _encoded_like(line: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9+/=]", "", line)
    if len(compact) < 180:
        return False
    try:
        base64.b64decode(compact[: min(len(compact), 400)], validate=False)
    except Exception:
        return False
    return True


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
