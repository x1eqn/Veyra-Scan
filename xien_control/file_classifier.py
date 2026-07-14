from __future__ import annotations

import zipfile
from pathlib import Path


JAVA_ARCHIVE_SUFFIXES = (
    ".jar",
    ".jar.disabled",
    ".jar.bak",
    ".jar.old",
    ".disabled",
    ".bak",
    ".old",
)

PE_TYPES = {
    ".exe": "PE_EXE",
    ".dll": "PE_DLL",
    ".scr": "PE_SCR",
    ".cpl": "PE_CPL",
    ".sys": "PE_SYS",
    ".ocx": "PE_OCX",
}

INSTALLER_TYPES = {
    ".msi": "INSTALLER_MSI",
    ".msix": "INSTALLER_MSIX",
    ".appx": "INSTALLER_APPX",
    ".appxbundle": "INSTALLER_APPXBUNDLE",
    ".msixbundle": "INSTALLER_MSIXBUNDLE",
}

SCRIPT_TYPES = {
    ".bat": "SCRIPT_BAT",
    ".cmd": "SCRIPT_CMD",
    ".ps1": "SCRIPT_PS1",
    ".vbs": "SCRIPT_VBS",
    ".js": "SCRIPT_JS",
    ".wsf": "SCRIPT_WSF",
}

ARCHIVE_TYPES = {
    ".zip": "ARCHIVE_ZIP",
    ".7z": "ARCHIVE_7Z",
    ".rar": "ARCHIVE_RAR",
}

SHORTCUT_TYPES = {
    ".lnk": "SHORTCUT_LNK",
    ".url": "SHORTCUT_URL",
}

SUPPORTED_EXTENSIONS = set(PE_TYPES) | set(INSTALLER_TYPES) | set(SCRIPT_TYPES) | set(ARCHIVE_TYPES) | set(SHORTCUT_TYPES) | {".jar"}


def classify_file(path: Path) -> str:
    name = path.name.lower()
    if any(name.endswith(suffix) for suffix in JAVA_ARCHIVE_SUFFIXES):
        return "JAVA_ARCHIVE"
    suffix = path.suffix.lower()
    if suffix in PE_TYPES:
        return PE_TYPES[suffix]
    if suffix in INSTALLER_TYPES:
        return INSTALLER_TYPES[suffix]
    if suffix in SCRIPT_TYPES:
        return SCRIPT_TYPES[suffix]
    if suffix in SHORTCUT_TYPES:
        return SHORTCUT_TYPES[suffix]
    if suffix == ".zip" and _zip_has_java_structure(path):
        return "JAVA_ARCHIVE"
    if suffix in ARCHIVE_TYPES:
        return ARCHIVE_TYPES[suffix]
    return "UNKNOWN"


def is_supported_file(path: Path) -> bool:
    return classify_file(path) != "UNKNOWN"


def is_pe_type(file_type: str) -> bool:
    return file_type.startswith("PE_")


def is_script_type(file_type: str) -> bool:
    return file_type.startswith("SCRIPT_")


def is_installer_type(file_type: str) -> bool:
    return file_type.startswith("INSTALLER_")


def is_shortcut_type(file_type: str) -> bool:
    return file_type.startswith("SHORTCUT_")


def is_archive_type(file_type: str) -> bool:
    return file_type.startswith("ARCHIVE_")


def _zip_has_java_structure(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist()[:4000]:
                lower = name.lower()
                if lower.endswith(".class") or lower in {"fabric.mod.json", "quilt.mod.json", "mcmod.info", "meta-inf/mods.toml"}:
                    return True
    except (OSError, zipfile.BadZipFile):
        return False
    return False
