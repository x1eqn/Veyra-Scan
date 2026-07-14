from __future__ import annotations

import os
import re
from pathlib import Path

from .class_strings import tokens_for_text
from .exe_models import ExeScanResult


TRUSTED_VENDOR_KEYWORDS = {
    "microsoft",
    "mojang",
    "oracle",
    "openjdk",
    "eclipse",
    "jetbrains",
    "nvidia",
    "advanced micro devices",
    "amd",
    "intel",
    "discord",
    "valve",
    "steam",
    "curseforge",
    "modrinth",
    "overwolf",
    "lunar",
    "badlion",
    "prismlauncher",
    "prism launcher",
}

DLL_CATEGORY_MAP = {
    "kernel32.dll": {"file_system", "process_control"},
    "ntdll.dll": {"process_control"},
    "user32.dll": {"windows_ui"},
    "gdi32.dll": {"windows_ui"},
    "advapi32.dll": {"registry", "service_control", "crypto"},
    "shell32.dll": {"file_system", "windows_ui"},
    "shlwapi.dll": {"file_system"},
    "wininet.dll": {"networking"},
    "winhttp.dll": {"networking"},
    "ws2_32.dll": {"networking"},
    "urlmon.dll": {"networking"},
    "crypt32.dll": {"crypto"},
    "bcrypt.dll": {"crypto"},
    "psapi.dll": {"process_control"},
    "dbghelp.dll": {"process_control"},
    "ole32.dll": {"windows_ui"},
    "oleaut32.dll": {"windows_ui"},
    "zlib1.dll": {"compression"},
    "python311.dll": {"scripting_runtime"},
    "vcruntime140.dll": {"installer_runtime"},
    "steam_api64.dll": {"game_runtime"},
    "openal32.dll": {"game_runtime"},
}

FUNCTION_CATEGORY_HINTS = {
    "regopenkey": "registry",
    "regsetvalue": "registry",
    "createfile": "file_system",
    "writefile": "file_system",
    "deletefile": "file_system",
    "internetopen": "networking",
    "internetconnect": "networking",
    "httpopen": "networking",
    "connect": "networking",
    "createremotethread": "process_control",
    "openprocess": "process_control",
    "virtualallocex": "process_control",
    "createservice": "service_control",
    "startservice": "service_control",
    "crypt": "crypto",
    "bcrypt": "crypto",
}


def classify_folder(path: Path) -> str:
    text = str(path).lower()
    home = str(Path.home()).lower()
    win = os.environ.get("WINDIR", r"C:\Windows").lower()
    program_files = [os.environ.get("ProgramFiles", r"C:\Program Files").lower(), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower()]
    startup_markers = ["start menu\\programs\\startup", "\\startup\\"]
    if text.startswith(win + "\\"):
        return "SYSTEM_WINDOWS"
    if any(text.startswith(root + "\\") for root in program_files if root):
        return "PROGRAM_FILES"
    if any(marker in text for marker in startup_markers):
        return "STARTUP"
    if "\\appdata\\local\\temp" in text or "\\temp\\" in text or text.endswith("\\temp"):
        return "TEMP"
    if "\\appdata\\roaming" in text:
        return "APPDATA_ROAMING"
    if "\\appdata\\local" in text:
        return "APPDATA_LOCAL"
    if text.startswith(home):
        if "\\downloads" in text:
            return "USER_DOWNLOADS"
        if "\\desktop" in text:
            return "USER_DESKTOP"
        if "\\documents" in text:
            return "USER_DOCUMENTS"
        if any(token in text for token in ("\\.minecraft", "\\minecraft", "\\modrinth", "\\prism", "\\multimc", "\\curseforge", "\\atlauncher", "\\technic")):
            return "MINECRAFT_LAUNCHER_FOLDER"
        if any(token in text for token in ("\\steamapps\\", "\\games\\", "\\riot games\\", "\\epic games\\")):
            return "GAME_FOLDER"
        return "UNKNOWN_USER_FOLDER"
    if any(token in text for token in ("\\.minecraft", "\\minecraft", "\\modrinth", "\\prism", "\\multimc", "\\curseforge")):
        return "MINECRAFT_LAUNCHER_FOLDER"
    if any(token in text for token in ("\\steamapps\\", "\\games\\", "\\epic games\\")):
        return "GAME_FOLDER"
    return "UNKNOWN_USER_FOLDER"


def import_categories(dlls: list[str], functions: list[str]) -> set[str]:
    categories: set[str] = set()
    for dll in dlls:
        categories.update(DLL_CATEGORY_MAP.get(dll.lower(), set()))
    for function in functions:
        compact = function.lower()
        for hint, category in FUNCTION_CATEGORY_HINTS.items():
            if hint in compact:
                categories.add(category)
    if not categories and (dlls or functions):
        categories.add("unknown")
    return categories


def apply_identity_context(result: ExeScanResult) -> None:
    info = result.pe.version_info
    result.company_name = info.get("CompanyName", "")
    result.product_name = info.get("ProductName", "")
    result.file_description = info.get("FileDescription", "")
    result.original_filename = info.get("OriginalFilename", "")
    result.internal_name = info.get("InternalName", "")
    useful = [result.company_name, result.product_name, result.file_description, result.original_filename, result.internal_name]
    result.metadata_empty = not any(value.strip() for value in useful)
    result.trusted_vendor = is_trusted_vendor(" ".join([result.company_name, result.product_name, result.signature.signer_subject]))
    filename_stem = result.path.stem.lower()
    identity_names = [result.original_filename, result.internal_name]
    for identity in identity_names:
        if not identity:
            continue
        stem = Path(identity).stem.lower()
        if stem and filename_stem and not _similar_name(filename_stem, stem):
            result.identity_mismatch = True
            result.evidence.append(f"Original/Internal name differs: {identity}")
            break
    if result.metadata_empty and result.signature.status in {"UNSIGNED", "UNKNOWN"}:
        result.evidence.append("empty version info")


def review_priority(result: ExeScanResult, newly_seen: bool = False) -> tuple[str, str]:
    category = result.folder_category
    unsigned = result.signature.status in {"UNSIGNED", "UNKNOWN"}
    if category == "STARTUP" and unsigned:
        return "URGENT", "unsigned executable in startup location"
    if category in {"TEMP", "APPDATA_LOCAL", "APPDATA_ROAMING"} and unsigned:
        if _randomish_filename(result.file_name):
            return "HIGH", "unsigned AppData/Temp executable with random-looking name"
        return "HIGH", "unsigned executable in user-writable folder"
    if category in {"USER_DOWNLOADS", "USER_DESKTOP"} and unsigned and newly_seen:
        return "HIGH", "new unsigned executable in Downloads/Desktop"
    if category == "SYSTEM_WINDOWS" and result.signature.status == "SIGNED_VALID" and result.trusted_vendor:
        return "VERY_LOW", "valid signed system executable"
    if category == "PROGRAM_FILES" and result.signature.status == "SIGNED_VALID" and result.trusted_vendor:
        return "LOW", "valid signed Program Files executable"
    return "NORMAL", ""


def is_trusted_vendor(text: str) -> bool:
    lower = text.lower()
    return any(keyword in lower for keyword in TRUSTED_VENDOR_KEYWORDS)


def _similar_name(left: str, right: str) -> bool:
    left_tokens = set(tokens_for_text(left))
    right_tokens = set(tokens_for_text(right))
    if not left_tokens or not right_tokens:
        return False
    if left_tokens.intersection(right_tokens):
        return True
    left_compact = "".join(left_tokens)
    right_compact = "".join(right_tokens)
    return left_compact in right_compact or right_compact in left_compact


def _randomish_filename(name: str) -> bool:
    stem = Path(name).stem
    compact = re.sub(r"[^A-Za-z0-9]", "", stem)
    if len(compact) < 10:
        return False
    digits = sum(char.isdigit() for char in compact)
    vowels = sum(char.lower() in "aeiou" for char in compact)
    return digits >= 3 and vowels <= max(1, len(compact) // 8)
