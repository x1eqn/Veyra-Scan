from __future__ import annotations

import datetime as dt
import json
import zipfile

from xien_control.jar_scanner import JarScanner
from xien_control.models import LauncherLocation, ScanSummary
from xien_control.report_writer import render_report


def test_suspicious_jar_report_snapshot(tmp_path):
    jar_path = tmp_path / "sodium-helper.jar"
    with zipfile.ZipFile(jar_path, "w") as jar:
        jar.writestr(
            "fabric.mod.json",
            json.dumps(
                {
                    "id": "sodium-helper",
                    "name": "Sodium Helper",
                    "environment": "client",
                    "entrypoints": {"client": ["com.example.ClientEntrypoint"]},
                    "mixins": ["sodium-helper.mixins.json"],
                    "depends": {"minecraft": "1.21.4", "fabricloader": ">=0.16.0"},
                }
            ),
        )
        jar.writestr(
            "sodium-helper.mixins.json",
            json.dumps({"package": "com.example.mixin", "client": ["ReachMixin"]}),
        )
        jar.writestr(
            "com/example/ClientEntrypoint.class",
            _class_bytes("com/example/ModuleManager", "com/example/features/combat/ReachFeature"),
        )
        jar.writestr(
            "com/example/ModuleManager.class",
            _class_bytes("com/example/features/combat/ReachFeature", "module.combat.reach.name"),
        )
        jar.writestr(
            "com/example/mixin/ReachMixin.class",
            _class_bytes("net/minecraft/client/network/ClientPlayerEntity", "reach distance range enabled"),
        )
        jar.writestr(
            "assets/sodiumhelper/lang/en_us.json",
            json.dumps({"module.combat.reach.name": "Reach", "setting.reach.distance": "Reach Distance"}),
        )

    location = LauncherLocation("test", "snapshot", tmp_path, "test")
    result = JarScanner(enable_cache=False).scan(jar_path, location)
    report = render_report(
        ScanSummary(
            started_at=dt.datetime(2026, 1, 1, 12, 0, 0),
            generated_at=dt.datetime(2026, 1, 1, 12, 0, 0),
            locations=[location],
            jar_results=[result],
        )
    )

    assert "Overall Status : HIGH_REVIEW" in report
    assert "MINECRAFT JAR FINDINGS" in report
    assert "Suspicious Jars: 1" in report
    assert "Verdict :" in report
    assert "Reason  :" in report
    assert "Evidence:" in report
    assert "Confidence:" in report
    assert "Why:" in report
    assert "Reach" in report or "reach" in report


def _class_bytes(*utf8_values: str) -> bytes:
    constants = []
    for value in utf8_values:
        encoded = value.encode("utf-8")
        constants.append(b"\x01" + len(encoded).to_bytes(2, "big") + encoded)
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + (len(constants) + 1).to_bytes(2, "big") + b"".join(constants)
