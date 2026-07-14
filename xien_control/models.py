from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path

from .exe_models import ExeScanResult, ExeScanSummary
from .static_models import ChangeSummary, InventoryResult, ScanHealth, StaticAnalysisResult


Severity = str
Verdict = str


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    category: str
    severity: Severity
    keywords: tuple[str, ...]
    description: str
    confidence_weight: float
    false_positive_note: str = ""


@dataclass
class LauncherLocation:
    launcher_name: str
    instance_name: str
    mods_path: Path
    source: str
    location_type: str = "mods"


@dataclass
class DetectionMatch:
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    confidence: float
    matched_keyword: str
    source_type: str
    evidence_preview: str
    explanation: str
    context_type: str = ""
    class_name: str = ""
    method_name: str = ""


@dataclass
class RiskBreakdown:
    score: int
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)


@dataclass
class JarScanResult:
    path: Path
    file_name: str
    sha256: str
    size_bytes: int
    last_modified: dt.datetime
    launcher_name: str
    instance_name: str
    class_count: int = 0
    string_count: int = 0
    manifest_found: bool = False
    meta_inf_count: int = 0
    detections: list[DetectionMatch] = field(default_factory=list)
    analysis_tokens: set[str] = field(default_factory=set, repr=False)
    source_tokens: dict[str, set[str]] = field(default_factory=dict, repr=False)
    risk_score: int = 0
    analysis_confidence_score: int = 0
    analysis_confidence: str = "Low"
    analysis_status: str = "FAILED_ANALYSIS"
    verdict: Verdict = "CLEAN"
    risk_reasons: list[str] = field(default_factory=list)
    error: str | None = None
    obfuscation_ratio: float = 0.0
    short_class_count: int = 0
    suspicious_package_hits: int = 0
    renamed_suspicious: bool = False
    truncated: bool = False
    loader_type: str = "Unknown"
    mod_id: str = ""
    mod_name: str = ""
    minecraft_versions: list[str] = field(default_factory=list)
    loader_versions: list[str] = field(default_factory=list)
    client_side: bool = False
    java_agent_manifest: bool = False
    java_agent_retransform: bool = False
    java_agent_redefine: bool = False
    java_agent_native_prefix: bool = False
    metadata_files_found: list[str] = field(default_factory=list)
    mixin_files_found: list[str] = field(default_factory=list)
    access_widener_files_found: list[str] = field(default_factory=list)
    service_entries_found: list[str] = field(default_factory=list)
    entrypoint_classes: set[str] = field(default_factory=set, repr=False)
    mixin_classes: set[str] = field(default_factory=set, repr=False)
    mixin_targets: dict[str, set[str]] = field(default_factory=dict, repr=False)
    access_widener_targets: set[str] = field(default_factory=set, repr=False)
    class_references: dict[str, set[str]] = field(default_factory=dict, repr=False)
    class_api_refs: dict[str, set[str]] = field(default_factory=dict, repr=False)
    class_feature_tokens: dict[str, set[str]] = field(default_factory=dict, repr=False)
    class_contexts: dict[str, set[str]] = field(default_factory=dict, repr=False)
    tree_summary: dict[str, int | float | str] = field(default_factory=dict, repr=False)
    sources_analyzed_count: int = 0
    classes_analyzed_count: int = 0
    resources_analyzed_count: int = 0
    strong_evidence_count: int = 0
    weak_evidence_count: int = 0
    known_hash_status: str = ""
    allowlisted: bool = False
    allowlist_notes: list[str] = field(default_factory=list)
    why_flagged: list[str] = field(default_factory=list)
    archive_type: str = "standard_jar"
    non_standard_archive: bool = False
    nested_parent: str = ""
    nested_path: str = ""
    nested_results: list["JarScanResult"] = field(default_factory=list, repr=False)
    structure_fingerprint: str = ""
    fuzzy_fingerprint: int = 0
    fingerprint_tokens: set[str] = field(default_factory=set, repr=False)
    module_system_score: int = 0
    review_priority: str = "NORMAL"
    review_priority_reason: str = ""
    confidence_reasons: list[str] = field(default_factory=list)
    related_files: list[str] = field(default_factory=list)
    correlation_notes: list[str] = field(default_factory=list)
    previous_scan_notes: list[str] = field(default_factory=list)
    cache_reused: bool = False
    instance_context: str = ""
    build_metadata: dict[str, str] = field(default_factory=dict)
    package_trust: str = "unknown"
    decoded_string_hits: list[str] = field(default_factory=list)
    obfuscated_string_score: int = 0
    decoder_signals: list[str] = field(default_factory=list)
    package_classifications: dict[str, str] = field(default_factory=dict)
    class_package_roles: dict[str, str] = field(default_factory=dict, repr=False)
    mod_owned_prefixes: set[str] = field(default_factory=set, repr=False)
    shaded_library_prefixes: set[str] = field(default_factory=set, repr=False)
    source_files: dict[str, str] = field(default_factory=dict, repr=False)
    local_variable_names: dict[str, set[str]] = field(default_factory=dict, repr=False)
    inner_class_names: dict[str, set[str]] = field(default_factory=dict, repr=False)
    annotation_refs: dict[str, set[str]] = field(default_factory=dict, repr=False)
    bootstrap_refs: dict[str, set[str]] = field(default_factory=dict, repr=False)
    parsed_attributes_count: int = 0
    numeric_constants: dict[str, list[float]] = field(default_factory=dict, repr=False)
    entity_descriptor_refs: int = 0
    player_descriptor_refs: int = 0
    render_descriptor_refs: int = 0
    input_descriptor_refs: int = 0
    network_descriptor_refs: int = 0
    bytecode_activity_score: int = 0
    class_roles: dict[str, str] = field(default_factory=dict, repr=False)
    setting_model_score: int = 0
    gui_context_score: int = 0
    token_vectors: dict[str, int] = field(default_factory=dict)
    family_id: str = ""
    family_similarity: float = 0.0
    filename_version: str = ""
    metadata_version: str = ""
    maven_version: str = ""
    implementation_version: str = ""
    mod_version: str = ""
    version_consistency: str = "MISSING"
    signature_status: str = "UNKNOWN"
    zip_anomalies: list[str] = field(default_factory=list)
    opaque_payload_paths: list[str] = field(default_factory=list)
    opaque_payload_formats: dict[str, str] = field(default_factory=dict)
    opaque_payload_bytes: int = 0
    opaque_payload_high_entropy: int = 0
    opaque_payload_zero_filled: int = 0
    class_version_counts: dict[int, int] = field(default_factory=dict)
    min_class_major: int = 0
    max_class_major: int = 0
    dominant_class_major: int = 0
    mixed_class_versions: bool = False
    declared_dependencies: set[str] = field(default_factory=set, repr=False)
    provided_ids: set[str] = field(default_factory=set, repr=False)
    conflicting_ids: set[str] = field(default_factory=set, repr=False)
    reachable_features: set[str] = field(default_factory=set, repr=False)
    feature_reachability: str = "UNKNOWN"
    entrypoint_validation: str = "UNKNOWN"
    modrinth_verified: bool = False
    modrinth_project_id: str = ""
    modrinth_version_id: str = ""
    modrinth_version_name: str = ""
    modrinth_version_number: str = ""
    modrinth_project_url: str = ""
    deep_audit_entries: int = 0
    deep_audit_bytes: int = 0
    deep_audit_sha256: str = ""
    deep_audit_high_compression_entries: int = 0
    deep_audit_duplicate_hashes: int = 0
    deep_audit_embedded_native: int = 0
    deep_audit_crc_error: str = ""
    deep_audit_class_entries: int = 0
    deep_audit_valid_class_entries: int = 0
    deep_audit_invalid_class_entries: int = 0
    deep_audit_nested_archives: int = 0
    deep_audit_encrypted_entries: int = 0
    deep_audit_suspicious_paths: int = 0
    deep_audit_max_compression_ratio: float = 0.0
    deep_audit_high_entropy_entries: int = 0
    deep_audit_max_entropy: float = 0.0
    deep_audit_feature_hits: list[str] = field(default_factory=list)


@dataclass
class ExecutableScanResult:
    path: Path
    file_name: str
    size_bytes: int
    last_modified: dt.datetime
    signature_status: str
    matched_indicators: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    risk_score: int = 0
    verdict: Verdict = "SUSPICIOUS"
    error: str | None = None


@dataclass
class ScanSummary:
    started_at: dt.datetime
    generated_at: dt.datetime
    locations: list[LauncherLocation] = field(default_factory=list)
    jar_results: list[JarScanResult] = field(default_factory=list)
    executable_results: list[ExeScanResult | ExecutableScanResult] = field(default_factory=list)
    exe_summary: ExeScanSummary = field(default_factory=ExeScanSummary)
    inventory_result: InventoryResult = field(default_factory=InventoryResult)
    static_results: list[StaticAnalysisResult] = field(default_factory=list)
    grouped_findings: dict[str, int] = field(default_factory=dict)
    change_summary: ChangeSummary = field(default_factory=ChangeSummary)
    scan_health: ScanHealth = field(default_factory=ScanHealth)
    official_version_jars: list[Path] = field(default_factory=list)
    skipped_errors: list[str] = field(default_factory=list)
    new_jars: int = 0
    changed_jars: int = 0
    removed_jars: int = 0
    renamed_or_similar_jars: int = 0
    important_changes: list[str] = field(default_factory=list)
    analysis_coverage: str = "Unknown"
    analysis_metrics: dict[str, int] = field(default_factory=dict)
    report_path: Path | None = None
    json_report_path: Path | None = None
    completed_categories: list[str] = field(default_factory=list)
    not_completed_categories: list[str] = field(default_factory=list)
    category_summaries: dict[str, str] = field(default_factory=dict)
    process_results: list[dict[str, object]] = field(default_factory=list)
    mousetweaks_findings: list[dict[str, object]] = field(default_factory=list)
    freecam_findings: list[dict[str, object]] = field(default_factory=list)
    autoclicker_findings: list[dict[str, object]] = field(default_factory=list)
    deleted_mod_findings: list[dict[str, object]] = field(default_factory=list)

    @property
    def scanned_jars(self) -> int:
        return len(self.jar_results)

    @property
    def suspicious_jars(self) -> list[JarScanResult]:
        output: list[JarScanResult] = []
        seen: set[str] = set()
        for item in self.jar_results:
            if item.verdict not in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}:
                continue
            key = item.sha256.lower() if item.sha256 else str(item.path).lower()
            if key in seen:
                continue
            seen.add(key)
            output.append(item)
        return output

    @property
    def suspicious_executables(self) -> list[ExecutableScanResult]:
        return [
            item
            for item in self.executable_results
            if item.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL", "REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}
        ]

    @property
    def low_signal_jars(self) -> list[JarScanResult]:
        return [item for item in self.jar_results if item.verdict == "LOW_SIGNAL"]

    @property
    def clean_jars(self) -> list[JarScanResult]:
        return [item for item in self.jar_results if item.verdict == "CLEAN"]
