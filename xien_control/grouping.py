from __future__ import annotations

from .exe_models import ExeScanResult
from .models import JarScanResult
from .static_models import StaticAnalysisResult


def grouped_findings(jars: list[JarScanResult], pe_results: list[ExeScanResult], static_results: list[StaticAnalysisResult]) -> dict[str, int]:
    groups = {
        "Unsigned user-folder applications": 0,
        "Startup-linked review items": 0,
        "Minecraft jar content findings": 0,
        "Installer packages needing review": 0,
        "Scripts referencing application files": 0,
        "Archive-contained review items": 0,
        "Duplicate files under different names": 0,
    }
    groups["Minecraft jar content findings"] = sum(1 for item in jars if item.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"})
    for item in pe_results:
        if item.signature.status in {"UNSIGNED", "UNKNOWN"} and item.folder_category in {"APPDATA_LOCAL", "APPDATA_ROAMING", "TEMP", "USER_DOWNLOADS", "USER_DESKTOP", "UNKNOWN_USER_FOLDER"} and item.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}:
            groups["Unsigned user-folder applications"] += 1
        if item.folder_category == "STARTUP" or item.review_priority == "URGENT":
            groups["Startup-linked review items"] += 1
        if item.duplicate_status:
            groups["Duplicate files under different names"] += 1
    for item in static_results:
        if item.file_type.startswith("INSTALLER") and item.review:
            groups["Installer packages needing review"] += 1
        if item.file_type.startswith("SCRIPT") and item.referenced_paths:
            groups["Scripts referencing application files"] += 1
        if item.file_type.startswith("ARCHIVE") and item.nested_items:
            groups["Archive-contained review items"] += 1
        if item.priority == "URGENT":
            groups["Startup-linked review items"] += 1
    return groups
