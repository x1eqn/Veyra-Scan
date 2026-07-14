from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .exe_models import ExeScanResult, PeInfo, PeSectionInfo, SignatureInfo


EXE_ANALYZER_VERSION = "2026-05-22.exe-1"


class ExeAnalysisCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.path = cache_dir / "exe_analysis_cache.json"
        self.data = _read_json(self.path)
        if not isinstance(self.data, dict) or self.data.get("analyzer_version") != EXE_ANALYZER_VERSION:
            self.data = {"analyzer_version": EXE_ANALYZER_VERSION, "items": {}}

    def get(self, path: Path, sha256: str, size: int, mtime: dt.datetime) -> ExeScanResult | None:
        key = _key(path, sha256, size, mtime)
        raw = self.data.get("items", {}).get(key)
        if not isinstance(raw, dict):
            return None
        result = result_from_cache(raw)
        if not result:
            return None
        result.path = path
        result.file_name = path.name
        result.cache_reused = True
        return result

    def put(self, result: ExeScanResult) -> None:
        key = _key(result.path, result.sha256, result.size_bytes, result.last_modified)
        self.data.setdefault("items", {})[key] = result_to_cache(result)

    def save(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")


def result_to_cache(result: ExeScanResult) -> dict:
    return {
        "path": str(result.path),
        "file_name": result.file_name,
        "size_bytes": result.size_bytes,
        "created_time": result.created_time.isoformat(),
        "last_modified": result.last_modified.isoformat(),
        "sha256": result.sha256,
        "file_type": result.file_type,
        "duplicate_status": result.duplicate_status,
        "duplicate_paths": result.duplicate_paths,
        "folder_category": result.folder_category,
        "review_priority": result.review_priority,
        "review_priority_reason": result.review_priority_reason,
        "confidence": result.confidence,
        "analysis_mode": result.analysis_mode,
        "pe": {
            "mz_header": result.pe.mz_header,
            "pe_signature": result.pe.pe_signature,
            "machine_type": result.pe.machine_type,
            "architecture": result.pe.architecture,
            "subsystem": result.pe.subsystem,
            "compile_timestamp": result.pe.compile_timestamp,
            "number_of_sections": result.pe.number_of_sections,
            "entry_point": result.pe.entry_point,
            "image_base": result.pe.image_base,
            "characteristics": result.pe.characteristics,
            "sections": [section.__dict__ for section in result.pe.sections],
            "imported_dlls": result.pe.imported_dlls,
            "imported_functions": result.pe.imported_functions[:200],
            "import_count": result.pe.import_count,
            "export_count": result.pe.export_count,
            "exported_names": result.pe.exported_names[:100],
            "overlay_size": result.pe.overlay_size,
            "overlay_offset": result.pe.overlay_offset,
            "icon_present": result.pe.icon_present,
            "manifest_present": result.pe.manifest_present,
            "rich_header_present": result.pe.rich_header_present,
            "debug_directory_present": result.pe.debug_directory_present,
            "pdb_path": result.pe.pdb_path,
            "tls_callbacks_present": result.pe.tls_callbacks_present,
            "delay_import_table_present": result.pe.delay_import_table_present,
            "relocation_table_present": result.pe.relocation_table_present,
            "exception_table_present": result.pe.exception_table_present,
            "load_config_present": result.pe.load_config_present,
            "bound_imports_present": result.pe.bound_imports_present,
            "certificate_table_present": result.pe.certificate_table_present,
            "imphash": result.pe.imphash,
            "package_type": result.pe.package_type,
            "clr_header_present": result.pe.clr_header_present,
            "dotnet_metadata_present": result.pe.dotnet_metadata_present,
            "dotnet_assembly_name": result.pe.dotnet_assembly_name,
            "dotnet_assembly_version": result.pe.dotnet_assembly_version,
            "dotnet_references": result.pe.dotnet_references,
            "dotnet_type_names": result.pe.dotnet_type_names,
            "permission_summary": result.pe.permission_summary,
            "version_info": result.pe.version_info,
            "parse_warnings": result.pe.parse_warnings,
        },
        "signature": result.signature.__dict__,
        "import_categories": sorted(result.import_categories),
        "string_categories": result.string_categories,
        "string_evidence": result.string_evidence,
        "company_name": result.company_name,
        "product_name": result.product_name,
        "file_description": result.file_description,
        "original_filename": result.original_filename,
        "internal_name": result.internal_name,
        "metadata_empty": result.metadata_empty,
        "identity_mismatch": result.identity_mismatch,
        "trusted_vendor": result.trusted_vendor,
        "structural_fingerprint": result.structural_fingerprint,
        "structural_summary": result.structural_summary,
        "reasons": result.reasons,
        "evidence": result.evidence,
        "risk_score": result.risk_score,
        "verdict": result.verdict,
        "error": result.error,
    }


def result_from_cache(raw: dict) -> ExeScanResult | None:
    try:
        result = ExeScanResult(
            path=Path(raw["path"]),
            file_name=str(raw.get("file_name", "")),
            size_bytes=int(raw["size_bytes"]),
            created_time=dt.datetime.fromisoformat(str(raw["created_time"])),
            last_modified=dt.datetime.fromisoformat(str(raw["last_modified"])),
            sha256=str(raw.get("sha256", "")),
            file_type=str(raw.get("file_type", "PE_EXE")),
        )
    except (KeyError, TypeError, ValueError):
        return None
    pe_raw = raw.get("pe", {})
    if isinstance(pe_raw, dict):
        result.pe = PeInfo(
            mz_header=bool(pe_raw.get("mz_header")),
            pe_signature=bool(pe_raw.get("pe_signature")),
            machine_type=str(pe_raw.get("machine_type", "")),
            architecture=str(pe_raw.get("architecture", "unknown")),
            subsystem=str(pe_raw.get("subsystem", "unknown")),
            compile_timestamp=str(pe_raw.get("compile_timestamp", "")),
            number_of_sections=int(pe_raw.get("number_of_sections", 0)),
            entry_point=int(pe_raw.get("entry_point", 0)),
            image_base=int(pe_raw.get("image_base", 0)),
            characteristics=int(pe_raw.get("characteristics", 0)),
            imported_dlls=list(pe_raw.get("imported_dlls", [])),
            imported_functions=list(pe_raw.get("imported_functions", [])),
            import_count=int(pe_raw.get("import_count", 0)),
            export_count=int(pe_raw.get("export_count", 0)),
            exported_names=list(pe_raw.get("exported_names", [])),
            overlay_size=int(pe_raw.get("overlay_size", 0)),
            overlay_offset=int(pe_raw.get("overlay_offset", 0)),
            icon_present=bool(pe_raw.get("icon_present")),
            manifest_present=bool(pe_raw.get("manifest_present")),
            rich_header_present=bool(pe_raw.get("rich_header_present")),
            debug_directory_present=bool(pe_raw.get("debug_directory_present")),
            pdb_path=str(pe_raw.get("pdb_path", "")),
            tls_callbacks_present=bool(pe_raw.get("tls_callbacks_present")),
            delay_import_table_present=bool(pe_raw.get("delay_import_table_present")),
            relocation_table_present=bool(pe_raw.get("relocation_table_present")),
            exception_table_present=bool(pe_raw.get("exception_table_present")),
            load_config_present=bool(pe_raw.get("load_config_present")),
            bound_imports_present=bool(pe_raw.get("bound_imports_present")),
            certificate_table_present=bool(pe_raw.get("certificate_table_present")),
            imphash=str(pe_raw.get("imphash", "")),
            package_type=str(pe_raw.get("package_type", "")),
            clr_header_present=bool(pe_raw.get("clr_header_present")),
            dotnet_metadata_present=bool(pe_raw.get("dotnet_metadata_present")),
            dotnet_assembly_name=str(pe_raw.get("dotnet_assembly_name", "")),
            dotnet_assembly_version=str(pe_raw.get("dotnet_assembly_version", "")),
            dotnet_references=list(pe_raw.get("dotnet_references", [])),
            dotnet_type_names=list(pe_raw.get("dotnet_type_names", [])),
            permission_summary=str(pe_raw.get("permission_summary", "")),
            version_info=dict(pe_raw.get("version_info", {})),
            parse_warnings=list(pe_raw.get("parse_warnings", [])),
        )
        result.pe.sections = [PeSectionInfo(**item) for item in pe_raw.get("sections", []) if isinstance(item, dict)]
    sig_raw = raw.get("signature", {})
    if isinstance(sig_raw, dict):
        result.signature = SignatureInfo(**{key: sig_raw.get(key, "") for key in ("status", "signer_subject", "signer_issuer")})
    for key, value in raw.items():
        if key in {"path", "file_name", "size_bytes", "created_time", "last_modified", "pe", "signature"}:
            continue
        if hasattr(result, key):
            setattr(result, key, value)
    result.import_categories = set(raw.get("import_categories", []))
    return result


def _key(path: Path, sha256: str, size: int, mtime: dt.datetime) -> str:
    return f"{str(path).lower()}:{sha256.lower()}:{size}:{mtime.isoformat()}:{EXE_ANALYZER_VERSION}"


def _read_json(path: Path) -> object:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
