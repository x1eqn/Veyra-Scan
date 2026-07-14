from __future__ import annotations

import datetime as dt
from pathlib import Path

from xien_control.exe_models import ExeScanResult, ExeScanSummary, SignatureInfo
from xien_control.models import ScanSummary
from xien_control.report_writer import render_report


def test_report_contains_windows_exe_section():
    now = dt.datetime(2026, 5, 22, 12, 0, 0)
    exe = ExeScanResult(
        path=Path(r"C:\Users\k\AppData\Local\Temp\example.exe"),
        file_name="example.exe",
        size_bytes=100,
        created_time=now,
        last_modified=now,
        sha256="b" * 64,
        folder_category="TEMP",
        review_priority="HIGH",
        review_priority_reason="unsigned executable in user-writable folder",
        signature=SignatureInfo(status="UNSIGNED"),
        risk_score=82,
        verdict="HIGH_REVIEW",
        reasons=["unsigned executable in AppData with empty version info and high-entropy section"],
        evidence=["section .text entropy 7.8", "no valid signature", "user AppData path"],
    )
    exe_summary = ExeScanSummary(results=[exe], new_since_last_scan=1, duplicate_hashes=0)

    report = render_report(
        ScanSummary(
            started_at=now,
            generated_at=now,
            executable_results=[exe],
            exe_summary=exe_summary,
        )
    )

    assert "VEYRA SCAN - FULL SCAN RESULT" in report
    assert "MINECRAFT JAR FINDINGS" in report
    assert "WINDOWS APPLICATION FINDINGS" in report
    assert "TOP EXE REVIEW ITEMS" in report
    assert "Verdict : HIGH_REVIEW" in report
    assert "Evidence: section .text entropy 7.8" in report
