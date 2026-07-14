from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileInventoryItem:
    path: Path
    file_name: str
    extension: str
    file_type: str
    size_bytes: int
    created_time: dt.datetime
    last_modified: dt.datetime
    folder_category: str
    quick_hash: str = ""
    source: str = "inventory"
    deep_candidate: bool = False
    deep_reason: str = ""
    analysis_priority: str = "LOW"
    analyzer_name: str = ""


@dataclass
class InventoryStats:
    scanned_folders: int = 0
    skipped_folders: int = 0
    permission_denied: int = 0
    files_seen: int = 0
    supported_files: int = 0
    duplicate_realpaths: int = 0
    errors_recovered: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class InventoryResult:
    items: list[FileInventoryItem] = field(default_factory=list)
    stats: InventoryStats = field(default_factory=InventoryStats)

    def count_type(self, *types: str) -> int:
        wanted = set(types)
        return sum(1 for item in self.items if item.file_type in wanted)


@dataclass
class StaticAnalysisResult:
    path: Path
    file_name: str
    file_type: str
    size_bytes: int
    last_modified: dt.datetime
    sha256: str = ""
    folder_category: str = "UNKNOWN_USER_FOLDER"
    verdict: str = "CLEAN"
    priority: str = "NORMAL"
    confidence: str = "LOW"
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    target_path: str = ""
    nested_items: list[str] = field(default_factory=list)
    referenced_paths: list[str] = field(default_factory=list)
    changed_status: str = ""
    cache_reused: bool = False
    error: str | None = None

    @property
    def review(self) -> bool:
        return self.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}


@dataclass
class DeepAnalysisQueue:
    items: list[FileInventoryItem] = field(default_factory=list)
    skipped_low_priority: int = 0
    reasons: dict[str, int] = field(default_factory=dict)


@dataclass
class ChangeSummary:
    new_application_files: int = 0
    changed_known_files: int = 0
    new_review_items: int = 0
    same_hash_different_names: int = 0
    recent_review_items_24h: int = 0
    recent_review_items_72h: int = 0
    important: list[str] = field(default_factory=list)


@dataclass
class ScanHealth:
    skipped_folders: int = 0
    permission_denied: int = 0
    unreadable_files: int = 0
    invalid_archives: int = 0
    invalid_pe_files: int = 0
    partial_analysis_items: int = 0
    signature_check_unknown: int = 0
    cache_errors_recovered: int = 0
    recovered_errors: int = 0
