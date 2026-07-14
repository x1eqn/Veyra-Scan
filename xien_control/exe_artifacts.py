from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .exe_models import ExeScanResult


class ExeArtifactDatabase:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.path = cache_dir / "exe_artifacts.json"
        raw = _read_json(self.path)
        self.data = raw if isinstance(raw, dict) else {"artifacts": {}, "paths": {}}
        self.data.setdefault("artifacts", {})
        self.data.setdefault("paths", {})

    def compare_previous(self, results: list[ExeScanResult]) -> dict[str, object]:
        new = 0
        changed = 0
        same_hash_different_path = 0
        important: list[str] = []
        artifacts = self.data.get("artifacts", {})
        paths = self.data.get("paths", {})
        for result in results:
            path_key = str(result.path).lower()
            previous_path = paths.get(path_key)
            previous_hash = previous_path.get("sha256") if isinstance(previous_path, dict) else None
            if not previous_path:
                new += 1
                if result.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}:
                    important.append(f"Recently added review item: {result.file_name}")
            elif previous_hash and previous_hash != result.sha256:
                changed += 1
                if result.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}:
                    important.append(f"Changed executable now needs review: {result.file_name}")
            previous_artifact = artifacts.get(result.sha256.lower())
            if isinstance(previous_artifact, dict):
                seen_paths = set(previous_artifact.get("seen_paths", []))
                if str(result.path) not in seen_paths and seen_paths:
                    same_hash_different_path += 1
                    result.duplicate_status = "same_hash_different_path"
                    result.duplicate_paths = sorted(seen_paths)[:4]
                    if result.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}:
                        important.append(f"Same executable seen under multiple names: {result.file_name}")
        return {
            "new": new,
            "changed": changed,
            "same_hash_different_path": same_hash_different_path,
            "important": important[:10],
        }

    def has_seen_path(self, path: Path) -> bool:
        return str(path).lower() in self.data.get("paths", {})

    def update(self, results: list[ExeScanResult]) -> None:
        now = dt.datetime.now().replace(microsecond=0).isoformat()
        artifacts = self.data.setdefault("artifacts", {})
        paths = self.data.setdefault("paths", {})
        for result in results:
            digest = result.sha256.lower()
            entry = artifacts.get(digest)
            if not isinstance(entry, dict):
                entry = {
                    "sha256": digest,
                    "first_seen": now,
                    "seen_paths": [],
                    "file_names": [],
                }
            entry["last_seen"] = now
            entry["seen_paths"] = sorted(set(entry.get("seen_paths", []) + [str(result.path)]))[:20]
            entry["file_names"] = sorted(set(entry.get("file_names", []) + [result.file_name]))[:20]
            entry["signer"] = result.signature.signer_subject
            entry["company_name"] = result.company_name
            entry["product_name"] = result.product_name
            entry["last_verdict"] = result.verdict
            entry["last_score"] = result.risk_score
            entry["review_priority"] = result.review_priority
            entry["structural_summary"] = result.structural_summary
            artifacts[digest] = entry
            paths[str(result.path).lower()] = {
                "sha256": digest,
                "size": result.size_bytes,
                "modified": result.last_modified.isoformat(),
                "last_seen": now,
            }

    def save(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> object:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
