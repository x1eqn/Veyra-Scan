import json
import zipfile

from xien_control.scan_orchestrator import ScanOrchestrator


def test_manual_jar_category_scans_only_selected_archive(tmp_path):
    jar_path = tmp_path / "selected.jar"
    with zipfile.ZipFile(jar_path, "w") as archive:
        archive.writestr("fabric.mod.json", json.dumps({"id": "selected", "name": "Selected"}))
        archive.writestr("dev/test/Main.class", b"not-a-real-class")

    scanner = ScanOrchestrator(
        log=lambda _tag, _message: None,
        progress=lambda _current, _total, _name: None,
        cache_dir=tmp_path / "cache",
        reports_dir=tmp_path / "reports",
        enable_launcher_discovery=False,
        manual_jar_paths=[jar_path],
    )
    summary = scanner.run_category("manual_jar")

    assert [item.path for item in summary.jar_results] == [jar_path]
    assert summary.completed_categories == ["manual_jar"]
