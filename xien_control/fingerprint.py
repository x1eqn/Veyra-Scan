from __future__ import annotations

import hashlib
from collections import Counter

from .class_strings import tokens_for_text
from .models import JarScanResult


def build_fingerprints(result: JarScanResult) -> None:
    tokens: set[str] = set()
    top_roots = str(result.tree_summary.get("top_package_roots", "")).split(",") if result.tree_summary else []
    tokens.update(token for root in top_roots for token in tokens_for_text(root))
    for source, source_tokens in result.source_tokens.items():
        if source == "filename":
            continue
        tokens.update(source_tokens)
    tokens.update(tokens_for_text(result.mod_id))
    tokens.update(tokens_for_text(result.mod_name))
    tokens.update(tokens_for_text(" ".join(result.metadata_files_found)))
    tokens.update(tokens_for_text(" ".join(result.mixin_files_found)))
    tokens.update(tokens_for_text(" ".join(result.access_widener_targets)))
    tokens.update(tokens_for_text(" ".join(result.build_metadata.values())))
    tokens.update(_bucket("class_count", result.class_count, (5, 20, 60, 150, 400)))
    tokens.update(_bucket("resource_count", result.resources_analyzed_count, (3, 10, 40, 100)))
    for match in result.detections:
        if match.source_type in {"filename", "heuristic", "hash", "correlation"}:
            continue
        tokens.update(tokens_for_text(match.category))
        tokens.update(tokens_for_text(match.rule_id))
    tokens = {token for token in tokens if len(token) > 1}
    result.fingerprint_tokens = tokens
    stable = "\n".join(sorted(tokens))
    result.structure_fingerprint = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:32]
    result.fuzzy_fingerprint = simhash64(tokens)


def similarity(left: JarScanResult, right: JarScanResult) -> float:
    if left.structure_fingerprint and left.structure_fingerprint == right.structure_fingerprint:
        return 1.0
    if left.fingerprint_tokens and right.fingerprint_tokens:
        inter = len(left.fingerprint_tokens & right.fingerprint_tokens)
        union = len(left.fingerprint_tokens | right.fingerprint_tokens)
        jaccard = inter / union if union else 0.0
    else:
        jaccard = 0.0
    if left.fuzzy_fingerprint and right.fuzzy_fingerprint:
        hamming = (left.fuzzy_fingerprint ^ right.fuzzy_fingerprint).bit_count()
        simhash_score = 1.0 - (hamming / 64)
    else:
        simhash_score = 0.0
    return round(max(jaccard, simhash_score), 3)


def simhash64(tokens: set[str]) -> int:
    weights: Counter[str] = Counter(tokens)
    vector = [0] * 64
    for token, weight in weights.items():
        digest = int(hashlib.blake2b(token.encode("utf-8"), digest_size=8).hexdigest(), 16)
        for index in range(64):
            vector[index] += weight if digest & (1 << index) else -weight
    out = 0
    for index, value in enumerate(vector):
        if value >= 0:
            out |= 1 << index
    return out


def _bucket(name: str, value: int, thresholds: tuple[int, ...]) -> set[str]:
    for threshold in thresholds:
        if value <= threshold:
            return {f"{name}_le_{threshold}"}
    return {f"{name}_gt_{thresholds[-1]}"}
