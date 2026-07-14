from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .exe_models import ExeScanResult
from .static_models import ChangeSummary, StaticAnalysisResult


class ApplicationChangeStory:
    def __init__(self, cache_dir: Path):
        self.path = cache_dir / "application_artifacts.json"
        raw = _read_json(self.path)
        self.data = raw if isinstance(raw, dict) else {"paths": {}, "hashes": {}}
        self.data.setdefault("paths", {})
        self.data.setdefault("hashes", {})

    def compare(self, results: list[ExeScanResult | StaticAnalysisResult]) -> ChangeSummary:
        summary = ChangeSummary()
        paths = self.data.get("paths", {})
        hashes = self.data.get("hashes", {})
        now = dt.datetime.now().replace(microsecond=0)
        for result in results:
            path_key = str(result.path).lower()
            digest = getattr(result, "sha256", "").lower()
            previous = paths.get(path_key)
            if not previous:
                summary.new_application_files += 1
                if _review(result):
                    summary.new_review_items += 1
                    summary.important.append(f"New review item: {result.file_name}")
            elif digest and previous.get("sha256") and previous.get("sha256") != digest:
                summary.changed_known_files += 1
            if digest and digest in hashes:
                seen_names = set(hashes[digest].get("file_names", []))
                if result.file_name not in seen_names and seen_names:
                    summary.same_hash_different_names += 1
            if _review(result):
                hours = (now - result.last_modified).total_seconds() / 3600
                if hours <= 24:
                    summary.recent_review_items_24h += 1
                if hours <= 72:
                    summary.recent_review_items_72h += 1
        return summary

    def update(self, results: list[ExeScanResult | StaticAnalysisResult]) -> None:
        now = dt.datetime.now().replace(microsecond=0).isoformat()
        paths = self.data.setdefault("paths", {})
        hashes = self.data.setdefault("hashes", {})
        for result in results:
            digest = getattr(result, "sha256", "").lower()
            paths[str(result.path).lower()] = {
                "sha256": digest,
                "file_type": getattr(result, "file_type", ""),
                "last_seen": now,
                "last_verdict": result.verdict,
                "last_score": result.risk_score,
            }
            if digest:
                entry = hashes.get(digest)
                if not isinstance(entry, dict):
                    entry = {"sha256": digest, "first_seen": now, "file_names": [], "seen_paths": []}
                entry["last_seen"] = now
                entry["file_names"] = sorted(set(entry.get("file_names", []) + [result.file_name]))[:20]
                entry["seen_paths"] = sorted(set(entry.get("seen_paths", []) + [str(result.path)]))[:20]
                hashes[digest] = entry

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")


def _review(result: ExeScanResult | StaticAnalysisResult) -> bool:
    return result.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}


def _read_json(path: Path) -> object:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
