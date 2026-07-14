from __future__ import annotations

import json

from xien_control.cache_manager import AnalysisCache
from xien_control.exe_cache import ExeAnalysisCache
from xien_control.location_baseline import LocationBaseline
from xien_control.scan_orchestrator import ScanOrchestrator


def test_corrupt_cache_json_is_reset_without_crash(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "analysis_cache.json").write_text("{not-json", encoding="utf-8")
    (cache_dir / "exe_analysis_cache.json").write_text("{not-json", encoding="utf-8")
    (cache_dir / "location_baseline.json").write_text("{not-json", encoding="utf-8")

    jar_cache = AnalysisCache(cache_dir)
    exe_cache = ExeAnalysisCache(cache_dir)
    baseline = LocationBaseline(cache_dir)

    assert isinstance(jar_cache.data, dict)
    assert isinstance(exe_cache.data, dict)
    assert isinstance(baseline.data, dict)


def test_orchestrator_no_files_found_still_writes_reports(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    reports = tmp_path / "reports"
    summary = ScanOrchestrator(
        log=lambda _tag, _msg: None,
        progress=lambda _done, _total, _label: None,
        cache_dir=tmp_path / "cache",
        reports_dir=reports,
        inventory_roots=[root],
        enable_launcher_discovery=False,
    ).run()

    assert summary.inventory_result.stats.supported_files == 0
    assert summary.report_path is not None
    assert summary.report_path.exists()
    assert summary.json_report_path is not None
    assert summary.json_report_path.exists()
    payload = json.loads(summary.json_report_path.read_text(encoding="utf-8"))
    assert payload["overall_status"] == "CLEAN"


def test_orchestrator_bad_jar_and_bad_exe_do_not_crash(tmp_path):
    root = tmp_path / "scan"
    root.mkdir()
    (root / "broken.jar").write_bytes(b"not a zip")
    (root / "broken.exe").write_bytes(b"not a pe")

    summary = ScanOrchestrator(
        log=lambda _tag, _msg: None,
        progress=lambda _done, _total, _label: None,
        cache_dir=tmp_path / "cache",
        reports_dir=tmp_path / "reports",
        inventory_roots=[root],
        enable_launcher_discovery=False,
    ).run()

    assert summary.report_path is not None and summary.report_path.exists()
    assert len(summary.jar_results) == 1
    assert len(summary.exe_summary.results) == 1
    assert summary.scan_health.invalid_pe_files >= 1
