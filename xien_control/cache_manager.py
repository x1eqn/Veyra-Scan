from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .models import DetectionMatch, JarScanResult


RULES_VERSION = "2026-07-13.modscan-deep-audit-9-connected-loader-runtime-probe"


class AnalysisCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.path = cache_dir / "analysis_cache.json"
        self.data = _read_json(self.path)
        if not isinstance(self.data, dict) or self.data.get("rules_version") != RULES_VERSION:
            self.data = {"rules_version": RULES_VERSION, "items": {}}

    def get(self, path: Path, sha256: str, size: int, mtime: dt.datetime) -> JarScanResult | None:
        key = _cache_key(sha256, size, mtime)
        raw = self.data.get("items", {}).get(key)
        if not isinstance(raw, dict):
            return None
        result = result_from_cache(raw)
        if result:
            result.path = path
            result.file_name = path.name
            result.cache_reused = True
        return result

    def put(self, result: JarScanResult) -> None:
        key = _cache_key(result.sha256, result.size_bytes, result.last_modified)
        self.data.setdefault("items", {})[key] = result_to_cache(result)

    def save(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")


def _cache_key(sha256: str, size: int, mtime: dt.datetime) -> str:
    return f"{sha256.lower()}:{size}:{mtime.isoformat()}"


def result_to_cache(result: JarScanResult) -> dict:
    return {
        "path": str(result.path),
        "file_name": result.file_name,
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
        "last_modified": result.last_modified.isoformat(),
        "launcher_name": result.launcher_name,
        "instance_name": result.instance_name,
        "risk_score": result.risk_score,
        "verdict": result.verdict,
        "analysis_confidence": result.analysis_confidence,
        "analysis_confidence_score": result.analysis_confidence_score,
        "analysis_status": result.analysis_status,
        "risk_reasons": result.risk_reasons,
        "why_flagged": result.why_flagged,
        "detections": [match.__dict__ for match in result.detections],
        "class_count": result.class_count,
        "string_count": result.string_count,
        "resources_analyzed_count": result.resources_analyzed_count,
        "metadata_files_found": result.metadata_files_found,
        "mixin_files_found": result.mixin_files_found,
        "loader_type": result.loader_type,
        "mod_id": result.mod_id,
        "mod_name": result.mod_name,
        "client_side": result.client_side,
        "modrinth_verified": result.modrinth_verified,
        "modrinth_project_id": result.modrinth_project_id,
        "modrinth_version_id": result.modrinth_version_id,
        "modrinth_version_name": result.modrinth_version_name,
        "modrinth_version_number": result.modrinth_version_number,
        "modrinth_project_url": result.modrinth_project_url,
        "java_agent_manifest": result.java_agent_manifest,
        "java_agent_retransform": result.java_agent_retransform,
        "java_agent_redefine": result.java_agent_redefine,
        "java_agent_native_prefix": result.java_agent_native_prefix,
        "structure_fingerprint": result.structure_fingerprint,
        "fuzzy_fingerprint": result.fuzzy_fingerprint,
        "fingerprint_tokens": sorted(result.fingerprint_tokens),
        "module_system_score": result.module_system_score,
        "review_priority": result.review_priority,
        "review_priority_reason": result.review_priority_reason,
        "archive_type": result.archive_type,
        "non_standard_archive": result.non_standard_archive,
        "nested_parent": result.nested_parent,
        "nested_path": result.nested_path,
        "instance_context": result.instance_context,
        "build_metadata": result.build_metadata,
        "package_trust": result.package_trust,
        "decoded_string_hits": result.decoded_string_hits,
        "obfuscated_string_score": result.obfuscated_string_score,
        "decoder_signals": result.decoder_signals,
        "package_classifications": result.package_classifications,
        "class_package_roles": result.class_package_roles,
        "mod_owned_prefixes": sorted(result.mod_owned_prefixes),
        "shaded_library_prefixes": sorted(result.shaded_library_prefixes),
        "source_files": result.source_files,
        "local_variable_names": {key: sorted(value) for key, value in result.local_variable_names.items()},
        "inner_class_names": {key: sorted(value) for key, value in result.inner_class_names.items()},
        "annotation_refs": {key: sorted(value) for key, value in result.annotation_refs.items()},
        "bootstrap_refs": {key: sorted(value) for key, value in result.bootstrap_refs.items()},
        "parsed_attributes_count": result.parsed_attributes_count,
        "numeric_constants": result.numeric_constants,
        "entity_descriptor_refs": result.entity_descriptor_refs,
        "player_descriptor_refs": result.player_descriptor_refs,
        "render_descriptor_refs": result.render_descriptor_refs,
        "input_descriptor_refs": result.input_descriptor_refs,
        "network_descriptor_refs": result.network_descriptor_refs,
        "bytecode_activity_score": result.bytecode_activity_score,
        "class_roles": result.class_roles,
        "setting_model_score": result.setting_model_score,
        "gui_context_score": result.gui_context_score,
        "token_vectors": result.token_vectors,
        "family_id": result.family_id,
        "family_similarity": result.family_similarity,
        "filename_version": result.filename_version,
        "metadata_version": result.metadata_version,
        "maven_version": result.maven_version,
        "implementation_version": result.implementation_version,
        "mod_version": result.mod_version,
        "version_consistency": result.version_consistency,
        "signature_status": result.signature_status,
        "zip_anomalies": result.zip_anomalies,
        "opaque_payload_paths": result.opaque_payload_paths,
        "opaque_payload_formats": result.opaque_payload_formats,
        "opaque_payload_bytes": result.opaque_payload_bytes,
        "opaque_payload_high_entropy": result.opaque_payload_high_entropy,
        "opaque_payload_zero_filled": result.opaque_payload_zero_filled,
        "class_version_counts": {str(key): value for key, value in result.class_version_counts.items()},
        "min_class_major": result.min_class_major,
        "max_class_major": result.max_class_major,
        "dominant_class_major": result.dominant_class_major,
        "mixed_class_versions": result.mixed_class_versions,
        "declared_dependencies": sorted(result.declared_dependencies),
        "provided_ids": sorted(result.provided_ids),
        "conflicting_ids": sorted(result.conflicting_ids),
        "reachable_features": sorted(result.reachable_features),
        "feature_reachability": result.feature_reachability,
        "entrypoint_validation": result.entrypoint_validation,
        "deep_audit_entries": result.deep_audit_entries,
        "deep_audit_bytes": result.deep_audit_bytes,
        "deep_audit_sha256": result.deep_audit_sha256,
        "deep_audit_high_compression_entries": result.deep_audit_high_compression_entries,
        "deep_audit_duplicate_hashes": result.deep_audit_duplicate_hashes,
        "deep_audit_embedded_native": result.deep_audit_embedded_native,
        "deep_audit_crc_error": result.deep_audit_crc_error,
        "deep_audit_class_entries": result.deep_audit_class_entries,
        "deep_audit_valid_class_entries": result.deep_audit_valid_class_entries,
        "deep_audit_invalid_class_entries": result.deep_audit_invalid_class_entries,
        "deep_audit_nested_archives": result.deep_audit_nested_archives,
        "deep_audit_encrypted_entries": result.deep_audit_encrypted_entries,
        "deep_audit_suspicious_paths": result.deep_audit_suspicious_paths,
        "deep_audit_max_compression_ratio": result.deep_audit_max_compression_ratio,
        "deep_audit_high_entropy_entries": result.deep_audit_high_entropy_entries,
        "deep_audit_max_entropy": result.deep_audit_max_entropy,
        "deep_audit_feature_hits": result.deep_audit_feature_hits,
    }


def result_from_cache(raw: dict) -> JarScanResult | None:
    try:
        result = JarScanResult(
            path=Path(raw.get("path", "")),
            file_name=str(raw.get("file_name", "")),
            sha256=str(raw["sha256"]),
            size_bytes=int(raw["size_bytes"]),
            last_modified=dt.datetime.fromisoformat(str(raw["last_modified"])),
            launcher_name=str(raw.get("launcher_name", "")),
            instance_name=str(raw.get("instance_name", "")),
        )
    except (KeyError, TypeError, ValueError):
        return None
    for item in raw.get("detections", []):
        if isinstance(item, dict):
            try:
                result.detections.append(DetectionMatch(**item))
            except TypeError:
                continue
    for key, value in raw.items():
        if key in {"path", "file_name", "sha256", "size_bytes", "last_modified", "launcher_name", "instance_name", "detections"}:
            continue
        if hasattr(result, key):
            setattr(result, key, value)
    result.fingerprint_tokens = set(raw.get("fingerprint_tokens", []))
    result.mod_owned_prefixes = set(raw.get("mod_owned_prefixes", []))
    result.shaded_library_prefixes = set(raw.get("shaded_library_prefixes", []))
    result.local_variable_names = {key: set(value) for key, value in raw.get("local_variable_names", {}).items() if isinstance(value, list)}
    result.inner_class_names = {key: set(value) for key, value in raw.get("inner_class_names", {}).items() if isinstance(value, list)}
    result.annotation_refs = {key: set(value) for key, value in raw.get("annotation_refs", {}).items() if isinstance(value, list)}
    result.bootstrap_refs = {key: set(value) for key, value in raw.get("bootstrap_refs", {}).items() if isinstance(value, list)}
    result.class_version_counts = {int(key): int(value) for key, value in raw.get("class_version_counts", {}).items()}
    result.declared_dependencies = set(raw.get("declared_dependencies", []))
    result.provided_ids = set(raw.get("provided_ids", []))
    result.conflicting_ids = set(raw.get("conflicting_ids", []))
    result.reachable_features = set(raw.get("reachable_features", []))
    return result


def _read_json(path: Path) -> object:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
