from __future__ import annotations

from .class_strings import tokens_for_text
from .models import DetectionMatch, JarScanResult


MODULE_TOKENS = {"module", "modulemanager", "manager", "category", "setting", "settings", "toggle", "keybind"}
FEATURE_TOKENS = {"triggerbot", "killaura", "reach", "velocity", "autoclicker", "esp", "xray", "scaffold", "aimassist", "aimbot"}
API_TOKENS = {"minecraftclient", "clientplayerentity", "livingentity", "playerentity", "gamerenderer", "mouse", "worldrenderer", "entityrenderer"}


def analyze_class_graph(result: JarScanResult) -> None:
    for entrypoint in result.entrypoint_classes:
        first_hop = result.class_references.get(entrypoint, set())
        if not first_hop:
            continue
        manager_refs = [ref for ref in first_hop if set(tokens_for_text(ref)).intersection(MODULE_TOKENS)]
        feature_refs = [ref for ref in first_hop if _feature_tokens(ref)]
        for manager in manager_refs[:6]:
            second_hop = result.class_references.get(manager, set())
            feature_refs.extend(ref for ref in second_hop if _feature_tokens(ref))
        api_linked = []
        for feature in feature_refs:
            refs = result.class_references.get(feature, set())
            if set(tokens_for_text(" ".join(refs))).intersection(API_TOKENS):
                api_linked.append(feature)
        if manager_refs and (feature_refs or api_linked):
            _add_detection(
                result,
                "CLASS_GRAPH_FEATURE_CHAIN",
                "Class graph feature chain",
                "Entrypoint references module manager and combat/render feature classes",
                f"{entrypoint} -> {manager_refs[0]} -> {(feature_refs or api_linked)[0]}",
                "high",
                0.86,
            )


def _feature_tokens(value: str) -> set[str]:
    tokens = set(tokens_for_text(value))
    compact = "".join(tokens_for_text(value))
    return {token for token in FEATURE_TOKENS if token in tokens or token in compact}


def _add_detection(
    result: JarScanResult,
    rule_id: str,
    rule_name: str,
    explanation: str,
    evidence: str,
    severity: str,
    confidence: float,
) -> None:
    if any(match.rule_id == rule_id and match.evidence_preview == evidence for match in result.detections):
        return
    result.detections.append(
        DetectionMatch(
            rule_id=rule_id,
            rule_name=rule_name,
            category="Graph",
            severity=severity,
            confidence=confidence,
            matched_keyword="entrypoint graph chain",
            source_type="graph",
            evidence_preview=evidence,
            explanation=explanation,
            context_type="class_graph",
        )
    )
