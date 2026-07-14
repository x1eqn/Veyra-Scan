from __future__ import annotations

import zipfile
from pathlib import Path


STANDARD_JAR_SUFFIXES = (".jar", ".jar.disabled", ".jar.disable", ".jar.bak", ".jar.backup", ".jar.old", ".jar.tmp", ".jar_")
JAVA_ARCHIVE_SUFFIXES = STANDARD_JAR_SUFFIXES + (".disabled", ".bak", ".old", ".zip", "")
MOD_METADATA_NAMES = {"fabric.mod.json", "quilt.mod.json", "mcmod.info", "meta-inf/mods.toml", "meta-inf/manifest.mf"}


def is_java_archive_candidate(path: Path, broad: bool = False) -> bool:
    name = path.name.lower()
    if any(name.endswith(suffix) for suffix in STANDARD_JAR_SUFFIXES):
        return True
    if not broad:
        return False
    suffix = path.suffix.lower()
    return suffix in {".disabled", ".bak", ".old", ".zip", ""}


def identify_java_archive(path: Path, broad: bool = False) -> tuple[bool, str]:
    if not is_java_archive_candidate(path, broad=broad):
        return False, "not_candidate"
    try:
        with path.open("rb") as fh:
            if fh.read(2) != b"PK":
                return False, "not_zip_header"
        with zipfile.ZipFile(path) as zf:
            names = [item.filename.replace("\\", "/").lower() for item in zf.infolist()[:2000]]
    except (OSError, zipfile.BadZipFile):
        return False, "unreadable_archive"
    has_class = any(name.endswith(".class") for name in names)
    has_metadata = any(name in MOD_METADATA_NAMES for name in names)
    if not has_class and not has_metadata:
        return False, "zip_without_java_mod_structure"
    standard = path.name.lower().endswith(".jar")
    return True, "standard_jar" if standard else "java_archive_nonstandard_extension"


def is_nested_archive_name(name: str) -> bool:
    lower = name.replace("\\", "/").lower()
    return (
        lower.endswith((".jar", ".zip", ".jar.disabled", ".jar.bak", ".jar.old"))
        and lower.startswith(
            (
                "meta-inf/jars/",
                "jars/",
                "libs/",
                "lib/",
                "nested/",
                "dependencies/",
                "meta-inf/libraries/",
            )
        )
    )
