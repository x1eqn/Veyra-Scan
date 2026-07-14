from __future__ import annotations

from .static_models import StaticAnalysisResult


def assign_confidence(result: StaticAnalysisResult, sources: int = 1, partial: bool = False) -> None:
    score = 25
    score += min(35, sources * 12)
    if result.sha256:
        score += 10
    if result.evidence:
        score += min(20, len(result.evidence) * 6)
    if partial:
        score -= 20
    if result.error:
        score -= 20
    if score >= 70:
        result.confidence = "HIGH"
    elif score >= 42:
        result.confidence = "MEDIUM"
    else:
        result.confidence = "LOW"
