from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path


ExeVerdict = str


@dataclass
class PeSectionInfo:
    name: str
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    raw_pointer: int = 0
    entropy: float = 0.0
    executable: bool = False
    readable: bool = False
    writable: bool = False
    unusual_name: bool = False


@dataclass
class PeInfo:
    mz_header: bool = False
    pe_signature: bool = False
    machine_type: str = ""
    architecture: str = "unknown"
    subsystem: str = "unknown"
    compile_timestamp: str = ""
    number_of_sections: int = 0
    entry_point: int = 0
    image_base: int = 0
    characteristics: int = 0
    sections: list[PeSectionInfo] = field(default_factory=list)
    imported_dlls: list[str] = field(default_factory=list)
    imported_functions: list[str] = field(default_factory=list)
    import_count: int = 0
    export_count: int = 0
    exported_names: list[str] = field(default_factory=list)
    overlay_size: int = 0
    overlay_offset: int = 0
    icon_present: bool = False
    manifest_present: bool = False
    rich_header_present: bool = False
    debug_directory_present: bool = False
    pdb_path: str = ""
    tls_callbacks_present: bool = False
    delay_import_table_present: bool = False
    relocation_table_present: bool = False
    exception_table_present: bool = False
    load_config_present: bool = False
    bound_imports_present: bool = False
    certificate_table_present: bool = False
    imphash: str = ""
    package_type: str = ""
    clr_header_present: bool = False
    dotnet_metadata_present: bool = False
    dotnet_assembly_name: str = ""
    dotnet_assembly_version: str = ""
    dotnet_references: list[str] = field(default_factory=list)
    dotnet_type_names: list[str] = field(default_factory=list)
    permission_summary: str = ""
    version_info: dict[str, str] = field(default_factory=dict)
    parse_warnings: list[str] = field(default_factory=list)

    @property
    def high_entropy_sections(self) -> list[PeSectionInfo]:
        return [section for section in self.sections if section.entropy >= 7.2 and section.raw_size >= 1024]

    @property
    def executable_writable_sections(self) -> list[PeSectionInfo]:
        return [section for section in self.sections if section.executable and section.writable]

    @property
    def unusual_sections(self) -> list[PeSectionInfo]:
        return [section for section in self.sections if section.unusual_name]


@dataclass
class SignatureInfo:
    status: str = "UNKNOWN"
    signer_subject: str = ""
    signer_issuer: str = ""


@dataclass
class ExeScanResult:
    path: Path
    file_name: str
    size_bytes: int
    created_time: dt.datetime
    last_modified: dt.datetime
    sha256: str = ""
    file_type: str = "PE_EXE"
    duplicate_status: str = ""
    duplicate_paths: list[str] = field(default_factory=list)
    folder_category: str = "UNKNOWN_USER_FOLDER"
    review_priority: str = "NORMAL"
    review_priority_reason: str = ""
    confidence: str = "LOW"
    analysis_mode: str = "FULL"
    pe: PeInfo = field(default_factory=PeInfo)
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    import_categories: set[str] = field(default_factory=set)
    string_categories: dict[str, int] = field(default_factory=dict)
    string_evidence: list[str] = field(default_factory=list)
    company_name: str = ""
    product_name: str = ""
    file_description: str = ""
    original_filename: str = ""
    internal_name: str = ""
    metadata_empty: bool = False
    identity_mismatch: bool = False
    trusted_vendor: bool = False
    structural_fingerprint: str = ""
    structural_summary: str = ""
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    risk_score: int = 0
    verdict: ExeVerdict = "CLEAN"
    cache_reused: bool = False
    error: str | None = None

    @property
    def signature_status(self) -> str:
        return self.signature.status


@dataclass
class ExeDiscoveryStats:
    scanned_folders: int = 0
    skipped_folders: int = 0
    exe_found: int = 0
    duplicate_realpaths: int = 0
    errors_recovered: int = 0
    discovery_notes: list[str] = field(default_factory=list)


@dataclass
class ExeScanSummary:
    results: list[ExeScanResult] = field(default_factory=list)
    stats: ExeDiscoveryStats = field(default_factory=ExeDiscoveryStats)
    elapsed_seconds: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    duplicate_hashes: int = 0
    new_since_last_scan: int = 0
    changed_since_last_scan: int = 0
    same_hash_different_path: int = 0
    important_changes: list[str] = field(default_factory=list)

    @property
    def scanned_exes(self) -> int:
        return len(self.results)

    @property
    def review_items(self) -> list[ExeScanResult]:
        return [item for item in self.results if item.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}]

    @property
    def high_review_items(self) -> list[ExeScanResult]:
        return [item for item in self.results if item.verdict in {"HIGH_REVIEW", "CRITICAL_REVIEW"}]

    @property
    def critical_review_items(self) -> list[ExeScanResult]:
        return [item for item in self.results if item.verdict == "CRITICAL_REVIEW"]

    @property
    def unsigned_user_folder_count(self) -> int:
        user_categories = {"USER_DOWNLOADS", "USER_DESKTOP", "USER_DOCUMENTS", "APPDATA_LOCAL", "APPDATA_ROAMING", "TEMP", "STARTUP", "UNKNOWN_USER_FOLDER"}
        return sum(1 for item in self.results if item.signature.status in {"UNSIGNED", "UNKNOWN"} and item.folder_category in user_categories)
