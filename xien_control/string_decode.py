from __future__ import annotations

import base64
import re
from urllib.parse import unquote


ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff]")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{12,}$")
HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}){4,}$")
LEET_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
DECODER_MARKERS = (
    "trigger", "autoclick", "clicker", "killaura", "freecam", "freelook",
    "mousetweaks", "xray", "wallhack", "reach", "velocity", "aimbot",
    "combat", "grim", "meteor", "impact", "baritone",
)


def decoded_variants(value: str) -> list[str]:
    variants: list[str] = []
    cleaned = ZERO_WIDTH_RE.sub("", value)
    cleaned = re.sub(r"[\s_.:\-]{2,}", " ", cleaned).strip()
    _add(variants, cleaned)
    try:
        _add(variants, cleaned.encode("utf-8").decode("unicode_escape"))
    except UnicodeError:
        pass
    if "%" in cleaned:
        _add(variants, unquote(cleaned))
    compact = re.sub(r"\s+", "", cleaned)
    if BASE64_RE.match(compact):
        for candidate in (compact, compact.replace("-", "+").replace("_", "/")):
            try:
                padded = candidate + "=" * (-len(candidate) % 4)
                decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            except (ValueError, UnicodeError):
                continue
            if _useful(decoded):
                _add(variants, decoded)
                _add_xor_variants(variants, decoded.encode("utf-8", errors="ignore"))
    # Small obfuscators commonly store a printable feature name as hex and XOR
    # it with one byte. Try that narrow, static form only; arbitrary bytecode
    # execution is intentionally never performed by the scanner.
    if HEX_RE.match(compact) and len(compact) <= 512:
        try:
            _add_xor_variants(variants, bytes.fromhex(compact))
        except ValueError:
            pass
    # Leetspeak decoding is useful only when digits are actually present;
    # translating ordinary JVM descriptors (for example class_1657) creates noise.
    leet = cleaned.translate(LEET_TABLE)
    if leet != cleaned and any(char in cleaned for char in "013457") and not ("/" in cleaned and ";" in cleaned):
        _add(variants, leet)
    return variants[:5]


def _add_xor_variants(values: list[str], payload: bytes) -> None:
    if not (4 <= len(payload) <= 256):
        return
    candidates: list[tuple[int, str]] = []
    for key in range(1, 256):
        decoded = bytes(value ^ key for value in payload)
        printable = sum(32 <= value < 127 or value in {9, 10, 13} for value in decoded)
        if printable / len(decoded) < 0.88:
            continue
        text = decoded.decode("utf-8", errors="ignore")
        if not _useful(text):
            continue
        lowered = text.lower()
        # Feature markers are the only reason an XOR candidate can influence
        # a verdict, so put those candidates first even when another key
        # happens to produce printable gibberish.
        marker_score = sum(lowered.count(marker) for marker in DECODER_MARKERS)
        alpha_ratio = sum(char.isalnum() or char.isspace() for char in text) / max(1, len(text))
        quality = marker_score * 1000 + int(alpha_ratio * 100)
        candidates.append((quality, text))
    for _, text in sorted(candidates, key=lambda item: item[0], reverse=True):
        _add(values, text)
        if len(values) >= 5:
            return


def _add(values: list[str], value: str) -> None:
    value = value.strip()
    if value and value not in values and _useful(value):
        values.append(value)


def _useful(value: str) -> bool:
    return 3 <= len(value) <= 240 and any(char.isalpha() for char in value)
