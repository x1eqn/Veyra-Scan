from __future__ import annotations

import datetime as dt
import zipfile

from xien_control.models import JarScanResult, LauncherLocation
from xien_control.mousetweaks_finder import MouseTweaksFinder


def _jar_result(path):
    return JarScanResult(
        path=path,
        file_name=path.name,
        sha256="0" * 64,
        size_bytes=path.stat().st_size,
        last_modified=dt.datetime.now(),
        launcher_name="Prism",
        instance_name="Test",
    )


def test_finds_mousetweaks_in_instance_log(tmp_path):
    mods = tmp_path / "instance" / "mods"
    logs = tmp_path / "instance" / "logs"
    mods.mkdir(parents=True)
    logs.mkdir()
    log = logs / "latest.log"
    log.write_text("[main/INFO] Loading MouseTweaks 2.26\n", encoding="utf-8")
    location = LauncherLocation("Prism", "Test", mods, "test")

    findings = MouseTweaksFinder().scan([location], [])

    assert len(findings) == 1
    assert findings[0]["source_type"] == "log"
    assert findings[0]["line"] == 1
    assert str(log) == findings[0]["path"]


def test_finds_mousetweaks_identity_inside_renamed_jar(tmp_path):
    jar_path = tmp_path / "innocent-name.jar"
    with zipfile.ZipFile(jar_path, "w") as archive:
        archive.writestr("a/b/C.class", b"prefix yalter/mousetweaks/MouseTweaks suffix")

    findings = MouseTweaksFinder().scan([], [_jar_result(jar_path)])

    assert len(findings) == 1
    assert findings[0]["source_type"] == "mod"
    assert findings[0]["file"] == "innocent-name.jar"
    assert "a/b/C.class" in findings[0]["evidence"]


def test_standalone_finder_discovers_mod_jars_from_instance(tmp_path):
    mods = tmp_path / "instance" / "mods"
    mods.mkdir(parents=True)
    jar_path = mods / "renamed.jar"
    with zipfile.ZipFile(jar_path, "w") as archive:
        archive.writestr("x/y/Z.class", b"Lyalter/mousetweaks/Config;")
    location = LauncherLocation("Prism", "Standalone", mods, "test")

    findings = MouseTweaksFinder().scan([location], [])

    assert len(findings) == 1
    assert findings[0]["instance"] == "Standalone"
    assert findings[0]["path"] == str(jar_path)


def test_finds_mousetweaks_config_file(tmp_path):
    mods = tmp_path / "instance" / "mods"
    config = tmp_path / "instance" / "config"
    mods.mkdir(parents=True)
    config.mkdir()
    config_path = config / "MouseTweaks.cfg"
    config_path.write_text("RMBTweak=1\n", encoding="utf-8")
    location = LauncherLocation("Prism", "Config", mods, "test")

    findings = MouseTweaksFinder().scan([location], [])

    assert len(findings) == 1
    assert findings[0]["source_type"] == "config"
    assert findings[0]["confidence"] == "high"
