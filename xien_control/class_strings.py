from __future__ import annotations

from dataclasses import dataclass
import re


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
TOKEN_RE = re.compile(r"[a-z0-9]+")
CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
LETTER_NUMBER_RE = re.compile(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{1,80}$")


STRICT_WORD_KEYWORDS = {
    "aura",
    "esp",
    "fly",
    "jesus",
    "phase",
    "reach",
    "speed",
    "tower",
    "spider",
    "bypass",
    "panic",
    "inject",
}


@dataclass(frozen=True)
class ClassConstants:
    utf8: list[str]
    method_names: list[str]
    field_names: list[str]
    class_refs: list[str]
    descriptors: list[str]
    parsed: bool


@dataclass(frozen=True)
class TextIndex:
    tokens: tuple[str, ...]
    token_set: frozenset[str]
    phrases: frozenset[str]
    compact: str


def extract_printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract readable ASCII/UTF-16LE-ish strings from class bytes."""
    out: list[str] = []
    seen: set[str] = set()
    for match in ASCII_RE.finditer(data):
        value = match.group(0).decode("utf-8", errors="ignore").strip()
        if len(value) >= min_length and value not in seen:
            seen.add(value)
            out.append(value)
    for match in UTF16LE_RE.finditer(data):
        raw = match.group(0)
        value = raw.decode("utf-16le", errors="ignore").strip()
        if len(value) >= min_length and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def parse_class_constants(data: bytes) -> ClassConstants:
    """Parse CONSTANT_Utf8 entries from a Java class file constant pool."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return ClassConstants([], [], [], [], [], False)

    utf8_values: list[str] = []
    offset = 8
    try:
        constant_pool_count = _u2(data, offset)
        offset += 2
        index = 1
        while index < constant_pool_count:
            tag = data[offset]
            offset += 1
            if tag == 1:  # CONSTANT_Utf8
                length = _u2(data, offset)
                offset += 2
                raw = data[offset : offset + length]
                offset += length
                value = raw.decode("utf-8", errors="replace").strip()
                if value:
                    utf8_values.append(value)
            elif tag in {3, 4}:  # Integer / Float
                offset += 4
            elif tag in {5, 6}:  # Long / Double
                offset += 8
                index += 1
            elif tag in {7, 8, 16, 19, 20}:  # Class / String / MethodType / Module / Package
                offset += 2
            elif tag in {9, 10, 11, 12, 17, 18}:  # refs / NameAndType / Dynamic / InvokeDynamic
                offset += 4
            elif tag == 15:  # MethodHandle
                offset += 3
            else:
                return ClassConstants([], [], [], [], [], False)
            if offset > len(data):
                return ClassConstants([], [], [], [], [], False)
            index += 1
    except (IndexError, ValueError):
        return ClassConstants([], [], [], [], [], False)

    method_names: list[str] = []
    field_names: list[str] = []
    class_refs: list[str] = []
    descriptors: list[str] = []
    for value in utf8_values:
        if value.startswith(("(", "[", "L")) or ";" in value:
            descriptors.append(value)
        if "/" in value or "." in value:
            class_refs.append(value)
        if _looks_like_member_name(value):
            method_names.append(value)
            field_names.append(value)

    return ClassConstants(
        utf8=_unique_limited(utf8_values, 6000),
        method_names=_unique_limited(method_names, 1500),
        field_names=_unique_limited(field_names, 1500),
        class_refs=_unique_limited(class_refs, 1500),
        descriptors=_unique_limited(descriptors, 1500),
        parsed=True,
    )


def tokens_for_text(text: str) -> list[str]:
    if not text:
        return []
    text = CAMEL_BOUNDARY_RE.sub(" ", text)
    text = LETTER_NUMBER_RE.sub(" ", text)
    return TOKEN_RE.findall(text.lower())


def token_set(text: str) -> set[str]:
    return set(tokens_for_text(text))


def prepare_text(text: str) -> TextIndex:
    tokens = tuple(tokens_for_text(text))
    token_values = frozenset(tokens)
    phrase_values = frozenset(ngrams(list(tokens), 2, 3))
    return TextIndex(tokens=tokens, token_set=token_values, phrases=phrase_values, compact="".join(tokens))


def ngrams(tokens: list[str], minimum: int = 2, maximum: int = 3) -> set[str]:
    out: set[str] = set()
    for size in range(minimum, maximum + 1):
        if len(tokens) < size:
            continue
        for index in range(0, len(tokens) - size + 1):
            out.add(" ".join(tokens[index : index + size]))
            out.add("".join(tokens[index : index + size]))
    return out


def normalize_for_match(text: str) -> str:
    return " ".join(tokens_for_text(text))


def compact_for_match(text: str) -> str:
    return "".join(tokens_for_text(text))


def path_tokens(path_text: str) -> set[str]:
    return token_set(path_text)


def keyword_matches(keyword: str, text: str) -> bool:
    return keyword_matches_index(keyword, prepare_text(text))


def keyword_matches_index(keyword: str, index: TextIndex) -> bool:
    keyword_l = keyword.lower().strip()
    if not keyword_l:
        return False

    keyword_tokens = tokens_for_text(keyword_l)
    if not keyword_tokens or not index.tokens:
        return False

    keyword_compact = "".join(keyword_tokens)
    keyword_phrase = " ".join(keyword_tokens)

    if len(keyword_tokens) > 1:
        return keyword_phrase in index.phrases or keyword_compact in index.phrases or keyword_compact in index.compact

    if keyword_compact in STRICT_WORD_KEYWORDS or len(keyword_compact) <= 4:
        return keyword_compact in index.token_set

    return keyword_compact in index.compact


def _u2(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ValueError("not enough bytes for u2")
    return int.from_bytes(data[offset : offset + 2], "big")


def _looks_like_member_name(value: str) -> bool:
    if not IDENTIFIER_RE.match(value):
        return False
    if value.startswith("<") or "/" in value or "." in value:
        return False
    return True


def _unique_limited(values: list[str], limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return out
