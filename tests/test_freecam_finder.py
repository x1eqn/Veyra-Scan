from __future__ import annotations

from xien_control.freecam_finder import FreecamFinder
from xien_control.models import LauncherLocation


def test_finds_freecam_config_file(tmp_path):
    mods = tmp_path / "instance" / "mods"
    config = tmp_path / "instance" / "config"
    mods.mkdir(parents=True)
    config.mkdir()
    config_path = config / "freecam.json"
    config_path.write_text('{"freezePlayer":false}', encoding="utf-8")
    location = LauncherLocation("Prism", "Config", mods, "test")

    findings = FreecamFinder().scan([location], [])

    assert len(findings) == 1
    assert findings[0]["source_type"] == "config"
    assert findings[0]["confidence"] == "high"
