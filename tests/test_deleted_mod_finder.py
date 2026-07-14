from __future__ import annotations

from xien_control.deleted_mod_finder import DeletedModTraceFinder
from xien_control.models import LauncherLocation


def test_deleted_mod_finder_reports_log_jar_missing_from_mods(tmp_path):
    instance = tmp_path / "instance"
    mods = instance / "mods"
    logs = instance / "logs"
    mods.mkdir(parents=True)
    logs.mkdir()
    (mods / "sodium-1.0.jar").write_bytes(b"PK")
    (logs / "latest.log").write_text("Loading sodium-1.0.jar\nLoading removed-freecam-2.0.jar\n", encoding="utf-8")
    location = LauncherLocation("Test", "Instance", mods, "test")

    findings = DeletedModTraceFinder().scan([location])

    names = {str(item["mod_name"]).lower() for item in findings}
    assert "removed-freecam-2.0.jar" in names
    assert "sodium-1.0.jar" not in names


def test_deleted_mod_finder_correlates_leftover_config(tmp_path):
    instance = tmp_path / "instance"
    mods = instance / "mods"
    logs = instance / "logs"
    config = instance / "config"
    mods.mkdir(parents=True)
    logs.mkdir()
    config.mkdir()
    (logs / "latest.log").write_text("Loaded oldclient-1.0.jar\n", encoding="utf-8")
    (config / "oldclient.json").write_text("{}", encoding="utf-8")
    location = LauncherLocation("Test", "Instance", mods, "test")

    findings = DeletedModTraceFinder().scan([location])

    assert any(item["source_type"] == "config" and item["mod_name"] == "oldclient" for item in findings)
