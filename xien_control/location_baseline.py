from __future__ import annotations

import json
from pathlib import Path

from .static_models import FileInventoryItem


class LocationBaseline:
    def __init__(self, cache_dir: Path):
        self.path = cache_dir / "location_baseline.json"
        raw = _read_json(self.path)
        self.data = raw if isinstance(raw, dict) else {"folders": {}}
        self.data.setdefault("folders", {})

    def is_new_location(self, item: FileInventoryItem) -> bool:
        return _folder_key(item.path) not in self.data.get("folders", {})

    def update(self, items: list[FileInventoryItem]) -> None:
        folders = self.data.setdefault("folders", {})
        for item in items:
            key = _folder_key(item.path)
            entry = folders.get(key)
            if not isinstance(entry, dict):
                entry = {"first_seen_types": [], "count": 0}
            entry["count"] = int(entry.get("count", 0)) + 1
            types = set(entry.get("first_seen_types", []))
            types.add(item.file_type)
            entry["first_seen_types"] = sorted(types)
            folders[key] = entry

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")


def _folder_key(path: Path) -> str:
    try:
        return str(path.parent.resolve()).lower()
    except OSError:
        return str(path.parent).lower()


def _read_json(path: Path) -> object:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
