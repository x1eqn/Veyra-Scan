from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
from pathlib import Path


SAFE_NAME_MARKERS = {
    "addon",
    "api",
    "client",
    "fabric",
    "forge",
    "fps",
    "iris",
    "lithium",
    "mod",
    "optifine",
    "performance",
    "sodium",
    "utility",
    "utils",
    "zoom",
}

JAR_SUFFIXES = (
    ".jar",
    ".jar.disabled",
    ".jar.disable",
    ".jar.bak",
    ".jar.backup",
    ".jar.old",
    ".jar.tmp",
    ".jar_",
)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_sha512_file(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            sha512.update(chunk)
    return sha256.hexdigest(), sha512.hexdigest()


def human_size(value: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{value} B"


def now_local() -> dt.datetime:
    return dt.datetime.now().replace(microsecond=0)


def clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, value))


def is_jar_like(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in JAR_SUFFIXES)


def is_safe_looking_name(file_name: str) -> bool:
    stem = Path(file_name).name.lower()
    stem = re.sub(r"\.jar(?:\..+)?$", "", stem)
    tokens = set(re.findall(r"[a-z0-9]+", stem))
    compact = re.sub(r"[^a-z0-9]+", "", stem)
    return bool(tokens.intersection(SAFE_NAME_MARKERS)) or compact in SAFE_NAME_MARKERS


def is_randomish_name(file_name: str) -> bool:
    stem = Path(file_name).stem.lower()
    compact = re.sub(r"[^a-z0-9]+", "", stem)
    if len(compact) < 12:
        return False
    vowels = sum(1 for char in compact if char in "aeiou")
    digits = sum(1 for char in compact if char.isdigit())
    return vowels <= max(1, len(compact) // 10) or digits >= len(compact) * 0.45


def safe_mtime(path: Path) -> dt.datetime:
    try:
        return dt.datetime.fromtimestamp(path.stat().st_mtime).replace(microsecond=0)
    except OSError:
        return dt.datetime.fromtimestamp(0)


def unique_report_path(reports_dir: Path, prefix: str = "xien_control_report") -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = now_local().strftime("%Y-%m-%d_%H-%M-%S")
    candidate = reports_dir / f"{prefix}_{stamp}.txt"
    counter = 2
    while candidate.exists():
        candidate = reports_dir / f"{prefix}_{stamp}_{counter}.txt"
        counter += 1
    return candidate


def env_path(name: str, fallback: Path) -> Path:
    value = os.environ.get(name)
    return Path(value) if value else fallback
