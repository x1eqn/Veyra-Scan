from __future__ import annotations

from .models import JarScanResult


def confidence_explanations(result: JarScanResult) -> list[str]:
    reasons: list[str] = []
    sources = {match.source_type for match in result.detections}
    if {"class_path", "string"}.issubset(sources):
        reasons.append("class path and constant pool agree")
    if result.metadata_files_found:
        reasons.append("metadata was available")
    if result.mixin_files_found or result.access_widener_files_found:
        reasons.append("mixin/access widener context was parsed")
    if result.parsed_attributes_count:
        reasons.append("bytecode attributes were parsed")
    if result.feature_reachability in {"REACHABLE", "POSSIBLY_REACHABLE"}:
        reasons.append("feature code is graph-reachable")
    if result.mod_owned_prefixes:
        reasons.append("mod-owned package area was identified")
    if len(sources) >= 3:
        reasons.append("multiple independent evidence sources")
    if result.analysis_status == "PARTIAL_ANALYSIS":
        reasons.append("analysis was partial")
    if result.analysis_status == "FAILED_ANALYSIS":
        reasons.append("analysis failed")
    return reasons[:3]


def report_reason(result: JarScanResult) -> str:
    if result.error:
        return result.error
    strong = [match for match in result.detections if match.severity in {"critical", "high"}]
    picked = strong[:2] if strong else result.detections[:2]
    if not picked:
        return "No direct rule match."
    return " / ".join(dict.fromkeys(match.explanation.split(".")[0] for match in picked))
