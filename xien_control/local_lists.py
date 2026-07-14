from __future__ import annotations

import json
from pathlib import Path


def load_known_hashes(search_roots: list[Path]) -> dict[str, dict[str, object]]:
    data = _load_first_json(search_roots, "known_hashes.json")
    return {
        "known_clean": _normalize_hash_map(data.get("known_clean", {}) if isinstance(data, dict) else {}),
        "known_review": _normalize_hash_map(data.get("known_review", {}) if isinstance(data, dict) else {}),
        "known_blocked": _normalize_hash_map(data.get("known_blocked", {}) if isinstance(data, dict) else {}),
    }


def load_allowlist(search_roots: list[Path]) -> dict[str, set[str]]:
    data = _load_first_json(search_roots, "allowlist.json")
    if not isinstance(data, dict):
        data = {}
    return {
        "allowed_hashes": _normalize_set(data.get("allowed_hashes", [])),
        "allowed_mod_ids": _normalize_set(data.get("allowed_mod_ids", [])),
    }


def _load_first_json(search_roots: list[Path], file_name: str) -> object:
    seen: set[str] = set()
    for root in search_roots:
        try:
            path = (root / file_name).resolve()
        except OSError:
            path = root / file_name
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        if not path.exists() or not path.is_file():
            continue
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _normalize_hash_map(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return {str(key).lower(): item for key, item in value.items()}
    if isinstance(value, list):
        return {str(item).lower(): True for item in value}
    return {}


def _normalize_set(value: object) -> set[str]:
    if isinstance(value, dict):
        return {str(key).lower() for key in value}
    if isinstance(value, list):
        return {str(item).lower() for item in value}
    return set()
