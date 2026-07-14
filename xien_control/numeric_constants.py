from __future__ import annotations

import re

from .class_strings import tokens_for_text
from .models import DetectionMatch, JarScanResult


def analyze_numeric_context(result: JarScanResult, class_name: str, text: str, numbers: list[float]) -> None:
    if not numbers:
        return
    tokens = set(tokens_for_text(f"{class_name} {text}"))
    strong_context = {"combat", "feature", "features", "mixin", "module", "modules", "setting", "settings"}
    interesting: list[float] = []
    if tokens.intersection({"reach", "attackrange"}) and tokens.intersection(strong_context | {"attack", "entity"}):
        interesting = [num for num in numbers if 3.0 <= float(num) <= 6.5]
    elif tokens.intersection({"cps", "clicker", "autoclicker"}) and tokens.intersection(strong_context):
        interesting = [num for num in numbers if 10 <= float(num) <= 30]
    elif tokens.intersection({"velocity", "knockback", "antikb"}) and tokens.intersection(strong_context | {"packet"}):
        interesting = [num for num in numbers if 0.0 <= float(num) <= 1.2]
    elif tokens.intersection({"aimassist", "aimbot", "silentaim"}) and tokens.intersection({"smooth", "rotation", "silent", "yaw", "pitch", "fov", "angle"}):
        interesting = [num for num in numbers if 0.0 <= float(num) <= 180.0]
    if not interesting:
        return
    value = sorted(set(round(float(num), 3) for num in interesting))[0]
    result.numeric_constants.setdefault(class_name, []).append(value)
    if any(match.rule_id == "NUMERIC_FEATURE_CONTEXT" and match.evidence_preview.startswith(class_name) for match in result.detections):
        return
    result.detections.append(
        DetectionMatch(
            rule_id="NUMERIC_FEATURE_CONTEXT",
            rule_name="Numeric feature context",
            category="Numeric",
            severity="medium",
            confidence=0.56,
            matched_keyword=str(value),
            source_type="numeric",
            evidence_preview=f"{class_name}: feature context with numeric constant {value}",
            explanation="Numeric constants match feature setting ranges only because related feature tokens are present nearby.",
            context_type="numeric_context",
        )
    )


def extract_numbers_from_text(text: str) -> list[float]:
    out: list[float] = []
    for value in re.findall(r"(?<![A-Za-z0-9])(?:\d+\.\d+|\d+)(?![A-Za-z0-9])", text):
        try:
            out.append(float(value))
        except ValueError:
            continue
    return out[:80]
