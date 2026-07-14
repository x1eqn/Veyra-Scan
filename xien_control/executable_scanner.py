from __future__ import annotations

import ctypes
import datetime as dt
from pathlib import Path
from typing import Callable
from uuid import UUID

from .class_strings import keyword_matches, tokens_for_text
from .models import ExecutableScanResult
from .risk import verdict_for_score
from .rules import RULES
from .utils import clamp, human_size


LogFn = Callable[[str, str], None]

KNOWN_CLIENT_EXE_INDICATORS = {
    "aristois",
    "bleachhack",
    "dopeclient",
    "dreamclient",
    "earthhack",
    "entropy",
    "fdpclient",
    "forgehax",
    "futureclient",
    "gamesense",
    "impactclient",
    "konas",
    "liquidbounce",
    "mathax",
    "meteor",
    "meteorclient",
    "novoline",
    "phobos",
    "ravenbplus",
    "riseclient",
    "rusherhack",
    "salhack",
    "sigmajello",
    "slinky",
    "tenacity",
    "thunderhack",
    "vape",
    "whiteout",
    "wurst",
    "wurstclient",
    "zeroday",
}

GENERIC_EXE_INDICATORS = {
    "aimassist",
    "aimbot",
    "antikb",
    "autoclicker",
    "bypass",
    "cheat",
    "clicker",
    "esp",
    "ghostclient",
    "hackclient",
    "injector",
    "killaura",
    "reach",
    "selfdestruct",
    "triggerbot",
    "velocity",
    "xray",
}

MINECRAFT_EXE_CONTEXT = {
    ".minecraft",
    "fabric",
    "forge",
    "launcher",
    "minecraft",
    "mod",
    "mods",
    "modrinth",
    "multimc",
    "prism",
    "quilt",
}

USER_DROP_LOCATIONS = {
    "appdata",
    "desktop",
    "documents",
    "downloads",
    "temp",
    "tmp",
}


class ExecutableScanner:
    def __init__(self, log: LogFn | None = None):
        self.log = log or (lambda _tag, _msg: None)

    def scan(self, exe_path: Path) -> ExecutableScanResult | None:
        indicators = executable_indicator_matches(exe_path)
        if not indicators:
            return None

        try:
            stat = exe_path.stat()
        except OSError as exc:
            return ExecutableScanResult(
                path=exe_path,
                file_name=exe_path.name,
                size_bytes=0,
                last_modified=dt.datetime.fromtimestamp(0),
                signature_status="UNKNOWN",
                matched_indicators=indicators,
                reasons=[f"Could not read executable metadata: {exc}"],
                risk_score=45,
                verdict="SUSPICIOUS",
                error=str(exc),
            )

        self.log("EXE", f"Checking executable signature: {exe_path.name} ({human_size(stat.st_size)})")
        signature_status = authenticode_status(exe_path)
        if signature_status == "VALID":
            return None

        score = 45
        indicator_set = {item.lower().replace(" ", "") for item in indicators}
        if indicator_set.intersection(KNOWN_CLIENT_EXE_INDICATORS):
            score += 30
        if any(item in indicator_set for item in {"killaura", "triggerbot", "aimbot", "autoclicker", "ghostclient"}):
            score += 20
        if signature_status not in {"UNSIGNED", "UNKNOWN"}:
            score += 10
        if _is_user_drop_location(exe_path):
            score += 8

        score = clamp(score)
        reasons = [
            "Executable name or path matched Minecraft cheat/client indicators.",
            f"Authenticode signature status: {signature_status}.",
        ]
        if _is_user_drop_location(exe_path):
            reasons.append("Executable is in a user-writable/drop location.")

        return ExecutableScanResult(
            path=exe_path,
            file_name=exe_path.name,
            size_bytes=stat.st_size,
            last_modified=dt.datetime.fromtimestamp(stat.st_mtime).replace(microsecond=0),
            signature_status=signature_status,
            matched_indicators=indicators[:10],
            reasons=reasons,
            risk_score=score,
            verdict=verdict_for_score(score),
        )


def looks_suspicious_executable_path(path: Path) -> bool:
    return bool(executable_indicator_matches(path))


def executable_indicator_matches(path: Path) -> list[str]:
    text = _path_text(path)
    tokens = set(tokens_for_text(text))
    compact = "".join(tokens_for_text(text))
    matches: list[str] = []

    for indicator in sorted(KNOWN_CLIENT_EXE_INDICATORS):
        if indicator in compact:
            matches.append(indicator)

    for indicator in sorted(GENERIC_EXE_INDICATORS):
        if indicator in compact:
            matches.append(indicator)

    if tokens.intersection(MINECRAFT_EXE_CONTEXT):
        for rule in RULES:
            if rule.severity not in {"medium", "high", "critical"}:
                continue
            for keyword in rule.keywords:
                if keyword_matches(keyword, text):
                    matches.append(keyword)

    if "client" in tokens and tokens.intersection(MINECRAFT_EXE_CONTEXT) and tokens.intersection({"hack", "ghost", "injector", "loader"}):
        matches.append("minecraft client loader")

    return _unique(matches)


def authenticode_status(path: Path) -> str:
    if not hasattr(ctypes, "windll"):
        return "UNKNOWN"
    try:
        result = _win_verify_trust(path)
    except (AttributeError, OSError, ValueError):
        return "UNKNOWN"

    code = int(result) & 0xFFFFFFFF
    if code == 0:
        return "VALID"
    if code in {0x800B0100, 0x800B0001, 0x800B0003}:
        return "UNSIGNED"
    if code in {0x800B0101, 0x800B0109, 0x80096010}:
        return "INVALID_SIGNATURE"
    return f"UNTRUSTED_SIGNATURE_0x{code:08X}"


def _win_verify_trust(path: Path) -> int:
    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.c_void_p),
            ("pgKnownSubject", ctypes.POINTER(GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_ulong),
            ("fdwRevocationChecks", ctypes.c_ulong),
            ("dwUnionChoice", ctypes.c_ulong),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.c_ulong),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_ulong),
            ("dwUIContext", ctypes.c_ulong),
        ]

    action = _guid_from_uuid(UUID("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"), GUID)
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO),
        str(path),
        None,
        None,
    )
    data = WINTRUST_DATA(
        ctypes.sizeof(WINTRUST_DATA),
        None,
        None,
        2,  # WTD_UI_NONE
        0,  # WTD_REVOKE_NONE
        1,  # WTD_CHOICE_FILE
        ctypes.pointer(file_info),
        0,
        None,
        None,
        0x00001000,  # WTD_CACHE_ONLY_URL_RETRIEVAL
        0,
    )
    wintrust = ctypes.windll.wintrust
    wintrust.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    return wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))


def _guid_from_uuid(value: UUID, guid_type):
    data4 = (ctypes.c_ubyte * 8).from_buffer_copy(value.bytes[8:])
    return guid_type(value.time_low, value.time_mid, value.time_hi_version, data4)


def _path_text(path: Path) -> str:
    return " ".join(str(part) for part in path.parts[-8:])


def _is_user_drop_location(path: Path) -> bool:
    return bool(set(tokens_for_text(_path_text(path))).intersection(USER_DROP_LOCATIONS))


def _unique(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.lower().strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(value)
    return out
