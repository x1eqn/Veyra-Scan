from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

from .fingerprint import similarity
from .models import DetectionMatch, JarScanResult


def correlate_results(results: list[JarScanResult]) -> None:
    by_hash: dict[str, list[JarScanResult]] = defaultdict(list)
    by_mod_id: dict[str, list[JarScanResult]] = defaultdict(list)
    by_package_root: dict[str, list[JarScanResult]] = defaultdict(list)
    by_fingerprint: dict[str, list[JarScanResult]] = defaultdict(list)
    for result in results:
        by_hash[result.sha256.lower()].append(result)
        if result.mod_id:
            by_mod_id[result.mod_id.lower()].append(result)
        if result.structure_fingerprint:
            by_fingerprint[result.structure_fingerprint].append(result)
        roots = str(result.tree_summary.get("top_package_roots", "")).split(",") if result.tree_summary else []
        for root in roots[:2]:
            if root:
                by_package_root[root].append(result)

    for group in list(by_hash.values()) + list(by_mod_id.values()) + list(by_fingerprint.values()):
        if len(group) <= 1:
            continue
        names = sorted({item.file_name for item in group})
        for item in group:
            others = [name for name in names if name != item.file_name]
            if others:
                item.related_files.extend(others[:5])
                item.correlation_notes.append("same hash/mod id/fingerprint seen in another file")

    for root, group in by_package_root.items():
        if len(group) <= 1:
            continue
        suspicious = [item for item in group if item.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}]
        if not suspicious:
            continue
        names = sorted({item.file_name for item in group})
        for item in group:
            item.related_files.extend(name for name in names if name != item.file_name)
            item.correlation_notes.append(f"shared package prefix: {root}")

    for index, left in enumerate(results):
        for right in results[index + 1 :]:
            if left.file_name == right.file_name:
                continue
            score = similarity(left, right)
            if score < 0.84:
                continue
            family_seed = "|".join(sorted([left.structure_fingerprint, right.structure_fingerprint, left.mod_id, right.mod_id]))
            family = f"family-{hashlib.sha1(family_seed.encode('utf-8', errors='ignore')).hexdigest()[:8]}"
            left.family_id = left.family_id or family
            right.family_id = right.family_id or family
            left.family_similarity = max(left.family_similarity, score)
            right.family_similarity = max(right.family_similarity, score)
            left.related_files.append(right.file_name)
            right.related_files.append(left.file_name)
            note = f"possible same-family jar detected: {int(score * 100)}%"
            left.correlation_notes.append(note)
            right.correlation_notes.append(note)

    for result in results:
        result.related_files = sorted(dict.fromkeys(result.related_files))[:8]
        result.correlation_notes = sorted(dict.fromkeys(result.correlation_notes))[:5]
        if result.correlation_notes and result.verdict in {"LOW_SIGNAL", "SUSPICIOUS", "HIGH_RISK", "CRITICAL"}:
            _add_correlation_detection(result)


def _add_correlation_detection(result: JarScanResult) -> None:
    if any(match.rule_id == "CROSS_JAR_CORRELATION" for match in result.detections):
        return
    result.detections.append(
        DetectionMatch(
            rule_id="CROSS_JAR_CORRELATION",
            rule_name="Related files correlation",
            category="Correlation",
            severity="medium" if result.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"} else "low",
            confidence=0.64,
            matched_keyword="related files",
            source_type="correlation",
            evidence_preview=", ".join(result.related_files[:4]) or "; ".join(result.correlation_notes[:2]),
            explanation="Other scanned jars share hash, mod id, package prefix, or structural fingerprint.",
            context_type="cross_jar",
        )
    )
