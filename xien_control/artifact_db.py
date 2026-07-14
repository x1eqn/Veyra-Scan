from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .fingerprint import similarity
from .models import JarScanResult


class ArtifactDatabase:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.path = cache_dir / "artifacts.json"
        self.previous_path = cache_dir / "previous_scan.json"
        self.data = _read_json(self.path)
        if not isinstance(self.data, dict):
            self.data = {"artifacts": {}}
        self.previous = _read_json(self.previous_path)
        if not isinstance(self.previous, dict):
            self.previous = {"items": []}

    def compare_previous(self, results: list[JarScanResult]) -> dict[str, object]:
        previous_items = [item for item in self.previous.get("items", []) if isinstance(item, dict)]
        by_path = {str(item.get("path", "")).lower(): item for item in previous_items}
        by_hash = {}
        by_fingerprint = {}
        previous_paths = set(by_path)
        for item in previous_items:
            by_hash.setdefault(str(item.get("sha256", "")).lower(), []).append(item)
            fp = str(item.get("structure_fingerprint", ""))
            if fp:
                by_fingerprint.setdefault(fp, []).append(item)

        current_paths = {str(item.path).lower() for item in results}
        new_count = 0
        changed_count = 0
        renamed_count = 0
        important: list[str] = []
        now = dt.datetime.now().replace(microsecond=0)

        for result in results:
            key = str(result.path).lower()
            previous = by_path.get(key)
            if not previous:
                new_count += 1
                if result.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}:
                    result.previous_scan_notes.append("new since previous scan")
                    important.append(f"Recently added suspicious jar: {result.file_name}")
            elif str(previous.get("sha256", "")).lower() != result.sha256.lower():
                changed_count += 1
                result.previous_scan_notes.append("changed since previous scan")
                if result.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}:
                    important.append(f"Changed suspicious jar: {result.file_name}")

            same_hash_elsewhere = [
                item for item in by_hash.get(result.sha256.lower(), [])
                if str(item.get("path", "")).lower() != key
            ]
            same_fp_elsewhere = [
                item for item in by_fingerprint.get(result.structure_fingerprint, [])
                if str(item.get("path", "")).lower() != key
            ]
            if same_hash_elsewhere or same_fp_elsewhere:
                renamed_count += 1
                result.previous_scan_notes.append("same hash/fingerprint seen before at another path")
                result.review_priority = _raise_priority(result.review_priority, "HIGH")
                result.review_priority_reason = result.review_priority_reason or "same artifact seen before under another name/path"
                first = (same_hash_elsewhere or same_fp_elsewhere)[0]
                important.append(f"Possible renamed copy from previous scan: {result.file_name} <- {Path(str(first.get('path', ''))).name}")

            age_hours = max(0.0, (now - result.last_modified).total_seconds() / 3600)
            if age_hours <= 24:
                result.review_priority = _raise_priority(result.review_priority, "HIGH")
                result.review_priority_reason = result.review_priority_reason or "modified in the last 24 hours"

        removed_count = len(previous_paths - current_paths)
        return {
            "new": new_count,
            "changed": changed_count,
            "removed": removed_count,
            "renamed_or_similar": renamed_count,
            "important": important[:12],
        }

    def update(self, results: list[JarScanResult]) -> None:
        now = dt.datetime.now().replace(microsecond=0).isoformat()
        artifacts = self.data.setdefault("artifacts", {})
        previous_items = []
        for result in results:
            item = {
                "path": str(result.path),
                "sha256": result.sha256,
                "file_size": result.size_bytes,
                "modified_time": result.last_modified.isoformat(),
                "structure_fingerprint": result.structure_fingerprint,
                "fuzzy_fingerprint": result.fuzzy_fingerprint,
                "verdict": result.verdict,
                "score": result.risk_score,
                "top_evidence_summary": [match.rule_name for match in result.detections[:5]],
                "mod_id": result.mod_id,
                "mod_name": result.mod_name,
            }
            previous_items.append(item)
            artifact = artifacts.setdefault(result.sha256, {"first_seen": now, "seen_paths": []})
            artifact["last_seen"] = now
            artifact["structure_fingerprint"] = result.structure_fingerprint
            artifact["fuzzy_fingerprint"] = result.fuzzy_fingerprint
            artifact["last_verdict"] = result.verdict
            artifact["last_score"] = result.risk_score
            artifact["mod_id"] = result.mod_id
            artifact["mod_name"] = result.mod_name
            paths = set(artifact.get("seen_paths", []))
            paths.add(str(result.path))
            artifact["seen_paths"] = sorted(paths)
        self.previous = {"generated_at": now, "items": previous_items}

    def save(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        self.previous_path.write_text(json.dumps(self.previous, indent=2, sort_keys=True), encoding="utf-8")

    def find_similar_artifact(self, result: JarScanResult, candidates: list[JarScanResult]) -> tuple[JarScanResult | None, float]:
        best: tuple[JarScanResult | None, float] = (None, 0.0)
        for other in candidates:
            if other is result:
                continue
            score = similarity(result, other)
            if score > best[1]:
                best = (other, score)
        return best


def _raise_priority(current: str, new: str) -> str:
    order = {"LOW": 0, "NORMAL": 1, "HIGH": 2, "URGENT": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


def _read_json(path: Path) -> object:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
