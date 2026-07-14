from __future__ import annotations

from .exe_models import ExeScanResult
from .static_models import InventoryStats, ScanHealth, StaticAnalysisResult


def build_scan_health(
    inventory_stats: InventoryStats,
    pe_results: list[ExeScanResult],
    static_results: list[StaticAnalysisResult],
    jar_partial: int = 0,
    invalid_archives: int = 0,
) -> ScanHealth:
    health = ScanHealth(
        skipped_folders=inventory_stats.skipped_folders,
        permission_denied=inventory_stats.permission_denied,
        invalid_archives=invalid_archives,
        partial_analysis_items=jar_partial,
        recovered_errors=inventory_stats.errors_recovered,
    )
    for item in pe_results:
        if item.error:
            health.unreadable_files += 1
        if not item.pe.pe_signature:
            health.invalid_pe_files += 1
        if item.signature.status == "UNKNOWN":
            health.signature_check_unknown += 1
        if item.analysis_mode in {"LIMITED", "HEADER_ONLY"}:
            health.partial_analysis_items += 1
    for item in static_results:
        if item.error:
            health.unreadable_files += 1
        if item.file_type.startswith("ARCHIVE") and item.error:
            health.invalid_archives += 1
    return health
