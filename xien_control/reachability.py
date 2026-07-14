from __future__ import annotations

from collections import deque

from .class_strings import tokens_for_text
from .models import DetectionMatch, JarScanResult


def analyze_reachability(result: JarScanResult) -> None:
    feature_classes = {name for name, tokens in result.class_feature_tokens.items() if tokens}
    if not feature_classes:
        result.feature_reachability = "UNKNOWN"
        return

    starts = set(result.entrypoint_classes)
    if not starts:
        starts = {name for name in result.class_references if _managerish(name)}

    reachable = _walk(result.class_references, starts, limit=2500)
    reachable_features = feature_classes.intersection(reachable)
    if reachable_features:
        result.reachable_features = reachable_features
        result.feature_reachability = "REACHABLE"
        _add(result, reachable_features)
        return

    manager_refs = {
        feature
        for manager, refs in result.class_references.items()
        if _managerish(manager)
        for feature in feature_classes
        if feature in refs or _same_package(manager, feature)
    }
    if manager_refs:
        result.reachable_features = manager_refs
        result.feature_reachability = "POSSIBLY_REACHABLE"
        _add(result, manager_refs)
    elif len(feature_classes) == 1 and not result.mixin_files_found and not result.source_tokens.get("translation"):
        result.feature_reachability = "ISOLATED"
    else:
        result.feature_reachability = "UNKNOWN"


def _walk(graph: dict[str, set[str]], starts: set[str], limit: int) -> set[str]:
    seen: set[str] = set()
    queue = deque(starts)
    while queue and len(seen) < limit:
        node = queue.popleft()
        if node in seen:
            continue
        seen.add(node)
        for ref in graph.get(node, set()):
            if ref not in seen:
                queue.append(ref)
    return seen


def _managerish(name: str) -> bool:
    tokens = set(tokens_for_text(name))
    return bool(tokens.intersection({"modulemanager", "featuremanager", "manager", "registry", "modules"}))


def _same_package(left: str, right: str) -> bool:
    return "/".join(left.split("/")[:-1]) == "/".join(right.split("/")[:-1])


def _add(result: JarScanResult, classes: set[str]) -> None:
    if any(match.rule_id == "REACHABLE_FEATURE_CONTEXT" for match in result.detections):
        return
    result.detections.append(
        DetectionMatch(
            rule_id="REACHABLE_FEATURE_CONTEXT",
            rule_name="Reachable feature context",
            category="Graph",
            severity="medium",
            confidence=0.72,
            matched_keyword="reachable feature",
            source_type="reachability",
            evidence_preview="feature class reachable from entrypoint/manager: " + ", ".join(sorted(classes)[:3]),
            explanation="Feature-looking code is connected to an entrypoint or module manager graph, reducing dead-code false positives.",
            context_type="class_graph",
        )
    )
