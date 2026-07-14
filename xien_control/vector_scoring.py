from __future__ import annotations

from collections import Counter

from .class_strings import tokens_for_text
from .models import DetectionMatch, JarScanResult


CATEGORY_VECTORS = {
    "combat": {"attack", "entity", "reach", "range", "click", "cps", "aura", "trigger", "bot", "velocity", "knockback", "rotation", "silent"},
    "movement": {"speed", "fly", "jump", "strafe", "sprint", "scaffold", "phase", "noclip"},
    "render": {"render", "world", "player", "overlay", "nametag", "esp", "xray", "tracer", "camera"},
    "automation": {"auto", "baritone", "mine", "nuker", "path", "bot"},
    "ui": {"screen", "button", "slider", "panel", "gui", "widget", "checkbox"},
    "setting": {"setting", "value", "mode", "enabled", "default", "min", "max", "keybind"},
    "minecraft_api": {"minecraftclient", "playerentity", "clientplayerentity", "entityhitresult", "mouse", "gamerenderer", "worldrenderer"},
}


def compute_token_vectors(result: JarScanResult) -> None:
    tokens = Counter(result.analysis_tokens)
    for role in result.class_roles.values():
        tokens.update(tokens_for_text(role))
    scores: dict[str, int] = {}
    for category, vector in CATEGORY_VECTORS.items():
        overlap = sum(tokens[token] for token in vector if token in tokens)
        scores[f"{category}_vector"] = min(100, overlap * 12)
    result.token_vectors = scores
    _add_vector_detections(result, scores)


def _add_vector_detections(result: JarScanResult, scores: dict[str, int]) -> None:
    direct_feature_rules = {
        match.rule_id
        for match in result.detections
        if match.severity in {"high", "critical"}
        and match.source_type in {"class_path", "config", "translation", "mixin", "string"}
        and not match.rule_id.startswith("CLIENT_")
    }
    if not result.class_feature_tokens and not direct_feature_rules:
        return
    combat = scores.get("combat_vector", 0)
    render = scores.get("render_vector", 0)
    api = scores.get("minecraft_api_vector", 0)
    setting = scores.get("setting_vector", 0)
    if combat >= 48 and api >= 24:
        _add(result, "TOKEN_VECTOR_COMBAT_CONTEXT", "Combat token vector context", "combat/api vector", combat + api)
    if render >= 48 and api >= 24:
        _add(result, "TOKEN_VECTOR_RENDER_CONTEXT", "Render token vector context", "render/api vector", render + api)
    if setting >= 36 and (combat >= 36 or render >= 36):
        _add(result, "TOKEN_VECTOR_SETTING_FEATURE_CONTEXT", "Setting feature token vector context", "setting/feature vector", setting + max(combat, render))


def _add(result: JarScanResult, rule_id: str, name: str, keyword: str, score: int) -> None:
    if any(match.rule_id == rule_id for match in result.detections):
        return
    result.detections.append(
        DetectionMatch(
            rule_id=rule_id,
            rule_name=name,
            category="Vector",
            severity="medium",
            confidence=0.6,
            matched_keyword=keyword,
            source_type="vector",
            evidence_preview=f"{keyword}: {score}",
            explanation="Token-vector density shows a feature category together with Minecraft/API or settings context.",
            context_type="token_vector",
        )
    )
