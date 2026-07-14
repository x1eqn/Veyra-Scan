from __future__ import annotations

from .class_strings import tokens_for_text
from .models import DetectionMatch, JarScanResult


MIXIN_ANNOTATIONS = {
    "mixin",
    "inject",
    "redirect",
    "modifyvariable",
    "modifyarg",
    "modifyconstant",
    "overwrite",
    "shadow",
    "unique",
    "invoker",
    "accessor",
}

SENSITIVE_TARGETS = {
    "minecraftclient",
    "clientplayerentity",
    "playerentity",
    "livingentity",
    "gamerenderer",
    "mouse",
    "keyboard",
    "clientconnection",
    "clientplaynetworkhandler",
    "entityrenderer",
    "worldrenderer",
}

FEATURES = {"reach", "velocity", "esp", "triggerbot", "killaura", "autoclicker", "aimassist", "aimbot", "antikb", "xray", "wallhack"}


def analyze_mixin_annotations(result: JarScanResult) -> None:
    for class_name, contexts in result.class_contexts.items():
        if "mixin" not in contexts:
            continue
        class_tokens = set(tokens_for_text(class_name))
        targets = result.mixin_targets.get(class_name, set()) | result.class_api_refs.get(class_name, set())
        target_tokens = set(tokens_for_text(" ".join(targets)))
        compact = "".join(class_tokens)
        feature_tokens = {
            feature
            for feature in FEATURES
            if feature in class_tokens or (len(feature) >= 7 and feature in compact)
        }
        if feature_tokens and target_tokens.intersection(SENSITIVE_TARGETS):
            _add(
                result,
                "MIXIN_INJECTION_FEATURE_TARGET",
                "Mixin injection feature target",
                "Mixin feature class targets sensitive Minecraft client/player/render classes.",
                f"{class_name}: targets {', '.join(sorted(target_tokens.intersection(SENSITIVE_TARGETS))[:4])}",
                "high",
                0.88,
            )


def record_annotation_context(result: JarScanResult, class_name: str, values: list[str]) -> None:
    tokens = set(tokens_for_text(" ".join(values)))
    annotations = tokens.intersection(MIXIN_ANNOTATIONS | {"eventhandler", "subscribeevent", "eventbussubscriber", "environment", "sideonly", "clientmodinitializer", "modinitializer", "onlyin"})
    if not annotations:
        return
    bucket = result.class_contexts.setdefault(class_name, set())
    if annotations.intersection(MIXIN_ANNOTATIONS):
        bucket.add("mixin")
    if annotations.intersection({"eventhandler", "subscribeevent", "eventbussubscriber", "clientmodinitializer", "modinitializer"}):
        bucket.add("event")
    if annotations.intersection({"clientmodinitializer", "environment", "sideonly", "onlyin"}):
        result.client_side = True


def _add(result: JarScanResult, rule_id: str, rule_name: str, explanation: str, evidence: str, severity: str, confidence: float) -> None:
    if any(match.rule_id == rule_id and match.evidence_preview == evidence for match in result.detections):
        return
    result.detections.append(
        DetectionMatch(
            rule_id=rule_id,
            rule_name=rule_name,
            category="Mixin",
            severity=severity,
            confidence=confidence,
            matched_keyword="mixin feature target",
            source_type="mixin",
            evidence_preview=evidence,
            explanation=explanation,
            context_type="mixin_injection",
        )
    )
