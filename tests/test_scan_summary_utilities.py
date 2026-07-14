from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from xien_control.change_story import ApplicationChangeStory
from xien_control.exe_models import ExeScanResult, SignatureInfo
from xien_control.exe_rules import review_priority
from xien_control.grouping import grouped_findings
from xien_control.json_report_writer import write_json_summary
from xien_control.models import JarScanResult, ScanSummary
from xien_control.priority import assign_priority
from xien_control.scan_health import build_scan_health
from xien_control.static_models import InventoryStats, StaticAnalysisResult


def test_priority_rules_separate_location_from_verdict():
    static = _static(Path(r"C:\Users\k\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.cmd"), "SCRIPT_CMD")
    static.verdict = "REVIEW"
    static.folder_category = "STARTUP"
    assign_priority(static)
    assert static.priority == "URGENT"

    exe = _exe(Path(r"C:\Program Files\Vendor\app.exe"))
    exe.folder_category = "PROGRAM_FILES"
    exe.signature = SignatureInfo(status="SIGNED_VALID", signer_subject="CN=Microsoft Corporation")
    exe.trusted_vendor = True
    assert review_priority(exe) == ("LOW", "valid signed Program Files executable")


def test_grouping_counts_related_review_items():
    exe = _exe(Path(r"C:\Users\k\AppData\Local\tool.exe"))
    exe.folder_category = "APPDATA_LOCAL"
    exe.signature = SignatureInfo(status="UNSIGNED")
    exe.verdict = "REVIEW"
    static = _static(Path(r"C:\Users\k\Downloads\payload.zip"), "ARCHIVE_ZIP")
    static.verdict = "REVIEW"
    static.nested_items = ["tools/runner.exe (PE_EXE, 2 bytes)"]

    groups = grouped_findings([], [exe], [static])

    assert groups["Unsigned user-folder applications"] == 1
    assert groups["Archive-contained review items"] == 1


def test_change_story_detects_new_changed_and_renamed_items(tmp_path):
    db = ApplicationChangeStory(tmp_path)
    first = _static(Path(r"C:\Users\k\Downloads\one.exe"), "PE_EXE", sha="a" * 64)
    first.verdict = "REVIEW"

    summary = db.compare([first])
    assert summary.new_application_files == 1
    assert summary.new_review_items == 1
    db.update([first])
    db.save()

    db2 = ApplicationChangeStory(tmp_path)
    changed = _static(Path(r"C:\Users\k\Downloads\one.exe"), "PE_EXE", sha="b" * 64)
    renamed = _static(Path(r"C:\Users\k\Downloads\two.exe"), "PE_EXE", sha="a" * 64)
    summary2 = db2.compare([changed, renamed])

    assert summary2.changed_known_files == 1
    assert summary2.same_hash_different_names == 1


def test_json_report_writer_outputs_short_summary(tmp_path):
    now = dt.datetime(2026, 5, 22, 12, 0, 0)
    static = _static(Path(r"C:\Users\k\Downloads\payload.zip"), "ARCHIVE_ZIP")
    static.verdict = "REVIEW"
    static.risk_score = 50
    summary = ScanSummary(started_at=now, generated_at=now, static_results=[static])
    txt_path = tmp_path / "xien_control_report.txt"

    json_path = write_json_summary(summary, txt_path)

    assert json_path is not None
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["overall_status"] == "REVIEW_NEEDED"
    assert payload["counts"]["static_findings"] == 1
    assert payload["report_txt_path"] == str(txt_path)


def test_scan_health_summarizes_recovered_errors():
    exe = _exe(Path(r"C:\Users\k\bad.exe"))
    exe.error = "bad pe"
    exe.signature = SignatureInfo(status="UNKNOWN")
    static = _static(Path(r"C:\Users\k\Downloads\bad.zip"), "ARCHIVE_ZIP")
    static.error = "invalid zip archive"

    health = build_scan_health(
        InventoryStats(skipped_folders=2, permission_denied=1, errors_recovered=3),
        [exe],
        [static],
        jar_partial=1,
    )

    assert health.skipped_folders == 2
    assert health.permission_denied == 1
    assert health.unreadable_files == 2
    assert health.invalid_archives == 1
    assert health.invalid_pe_files == 1
    assert health.signature_check_unknown == 1
    assert health.partial_analysis_items == 1


def test_suspicious_jars_deduplicate_same_hash():
    now = dt.datetime(2026, 5, 22, 12, 0, 0)
    left = JarScanResult(Path("one/moreculling.jar"), "moreculling.jar", "a" * 64, 1, now, "test", "one", verdict="HIGH_RISK")
    right = JarScanResult(Path("two/moreculling.jar"), "moreculling.jar", "a" * 64, 1, now, "test", "two", verdict="HIGH_RISK")
    summary = ScanSummary(started_at=now, generated_at=now, jar_results=[left, right])
    assert len(summary.suspicious_jars) == 1


def _exe(path: Path) -> ExeScanResult:
    now = dt.datetime(2026, 5, 22, 12, 0, 0)
    return ExeScanResult(
        path=path,
        file_name=path.name,
        size_bytes=100,
        created_time=now,
        last_modified=now,
        sha256="c" * 64,
    )


def _static(path: Path, file_type: str, sha: str = "d" * 64) -> StaticAnalysisResult:
    now = dt.datetime(2026, 5, 22, 12, 0, 0)
    return StaticAnalysisResult(
        path=path,
        file_name=path.name,
        file_type=file_type,
        size_bytes=100,
        last_modified=now,
        sha256=sha,
        folder_category="USER_DOWNLOADS",
    )
