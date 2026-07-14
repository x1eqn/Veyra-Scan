from __future__ import annotations

import datetime as dt
from pathlib import Path

from xien_control.exe_models import ExeScanResult, PeInfo, PeSectionInfo, SignatureInfo
from xien_control.exe_risk import score_exe


def test_unsigned_appdata_high_entropy_model_high_review():
    result = _base_result(Path(r"C:\Users\k\AppData\Local\Temp\chrome_update.exe"))
    result.folder_category = "TEMP"
    result.signature = SignatureInfo(status="UNSIGNED")
    result.metadata_empty = True
    result.pe = PeInfo(
        mz_header=True,
        pe_signature=True,
        sections=[PeSectionInfo(name=".packed", raw_size=4096, entropy=7.8, executable=True, readable=True, writable=False, unusual_name=True)],
        imported_dlls=["wininet.dll", "advapi32.dll"],
        imported_functions=["wininet.dll!InternetOpenA", "advapi32.dll!RegOpenKeyExA"],
        import_count=2,
    )
    result.import_categories = {"networking", "registry"}

    score_exe(result)

    assert result.verdict in {"HIGH_REVIEW", "CRITICAL_REVIEW"}
    assert result.risk_score >= 70
    assert any("unsigned executable" in reason for reason in result.reasons)


def test_valid_signed_program_files_model_low_score():
    result = _base_result(Path(r"C:\Program Files\Vendor\app.exe"))
    result.folder_category = "PROGRAM_FILES"
    result.signature = SignatureInfo(status="SIGNED_VALID", signer_subject="CN=Microsoft Corporation")
    result.trusted_vendor = True
    result.metadata_empty = False
    result.company_name = "Microsoft Corporation"
    result.pe = PeInfo(mz_header=True, pe_signature=True, imported_dlls=["wininet.dll", "advapi32.dll"], import_count=30)
    result.import_categories = {"networking", "registry"}

    score_exe(result)

    assert result.verdict in {"CLEAN", "LOW_SIGNAL"}
    assert result.risk_score < 45


def _base_result(path: Path) -> ExeScanResult:
    now = dt.datetime(2026, 5, 22, 12, 0, 0)
    return ExeScanResult(path=path, file_name=path.name, size_bytes=4096, created_time=now, last_modified=now, sha256="a" * 64)
