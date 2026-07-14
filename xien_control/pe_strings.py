from __future__ import annotations

import re


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract_pe_strings(data: bytes, limit: int = 6000) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for regex, encoding in ((ASCII_RE, "utf-8"), (UTF16_RE, "utf-16le")):
        for match in regex.finditer(data):
            try:
                value = match.group(0).decode(encoding, errors="ignore").strip()
            except UnicodeError:
                continue
            if len(value) < 4 or value in seen:
                continue
            seen.add(value)
            out.append(value)
            if len(out) >= limit:
                return out
    return out


def classify_strings(strings: list[str]) -> tuple[dict[str, int], list[str]]:
    counts = {
        "path_like": 0,
        "url_like": 0,
        "registry_like": 0,
        "command_like": 0,
        "config_like": 0,
        "random_like": 0,
        "human_readable": 0,
    }
    evidence: list[str] = []
    for value in strings[:3000]:
        lower = value.lower()
        category = ""
        if "http://" in lower or "https://" in lower or re.search(r"\b[a-z0-9.-]+\.(com|net|org|gg|io|ru|cn)\b", lower):
            category = "url_like"
        elif "\\software\\" in lower or lower.startswith(("hkey_", "hkcu", "hklm")):
            category = "registry_like"
        elif re.search(r"[a-z]:\\", value, re.IGNORECASE) or "/" in value and "\\" in value:
            category = "path_like"
        elif any(token in lower for token in ("powershell", "cmd.exe", "rundll32", "reg add", "schtasks", "wmic", "start-process")):
            category = "command_like"
        elif "=" in value and len(value) <= 180:
            category = "config_like"
        elif _randomish(value):
            category = "random_like"
        elif len(value.split()) >= 2:
            category = "human_readable"
        if category:
            counts[category] += 1
            if len(evidence) < 6 and category in {"url_like", "registry_like", "command_like", "path_like"}:
                evidence.append(f"{category}: {value[:120]}")
    return counts, evidence


def parse_version_info_from_strings(strings: list[str]) -> dict[str, str]:
    wanted = {
        "CompanyName",
        "ProductName",
        "FileDescription",
        "OriginalFilename",
        "InternalName",
        "FileVersion",
        "ProductVersion",
    }
    found: dict[str, str] = {}
    for index, value in enumerate(strings):
        key = value.strip().strip("\x00")
        if key not in wanted or key in found:
            continue
        for candidate in strings[index + 1 : index + 5]:
            cleaned = candidate.strip().strip("\x00")
            if cleaned and cleaned not in wanted and len(cleaned) <= 180:
                found[key] = cleaned
                break
    return found


def _randomish(value: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]", "", value)
    if len(compact) < 12:
        return False
    letters = sum(char.isalpha() for char in compact)
    digits = sum(char.isdigit() for char in compact)
    vowels = sum(char.lower() in "aeiou" for char in compact)
    return digits >= 4 and letters >= 4 and vowels <= max(1, letters // 8)
