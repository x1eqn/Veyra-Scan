from __future__ import annotations

import datetime as dt
from pathlib import Path

from xien_control.gui import _evidence_html, _summary_html
from xien_control.models import DetectionMatch, JarScanResult, ScanSummary


def test_evidence_html_contains_class_method_mixin_and_constant():
    item = JarScanResult(Path("helper.jar"), "helper.jar", "a" * 64, 10, dt.datetime.now(), "test", "test")
    item.detections.append(DetectionMatch(
        "TEST", "Feature behavior", "Combat", "high", 0.9, "triggerbot",
        "opcode", "com/x/Feature#tick: triggerbot", "Behavior matched.",
        class_name="com.x.Feature", method_name="tick",
    ))
    item.mixin_targets["com/x/Mixin"] = {"net/minecraft/client/MinecraftClient"}

    html = _evidence_html(item)

    assert "com.x.Feature#tick" in html
    assert "triggerbot" in html
    assert "Mixin targets" in html


def test_javaw_summary_groups_strong_and_weak_evidence():
    now = dt.datetime.now()
    summary = ScanSummary(started_at=now, generated_at=now, completed_categories=["javaw_scan"])
    summary.process_results = [{
        "pid": 42,
        "process_name": "javaw.exe",
        "executable": r"C:\Java\javaw.exe",
        "scanned_bytes": 1048576,
        "readable_bytes_seen": 2097152,
        "scanned_regions": 4,
        "successful_regions": 4,
        "memory_read_success_percent": 100.0,
        "memory_coverage_quality": "Complete map",
        "runtime_class_origins": [{
            "class_name": "com.example.TriggerBot", "jar_path": r"C:\mods\helper.jar",
            "class_entry": "com/example/TriggerBot.class", "address": "0x99",
            "class_present_on_disk": True,
        }],
        "private_executable_regions": 3,
        "private_executable_bytes": 4096,
        "hidden_pe_regions": ["0x5000"],
        "private_exec_thread_starts": [{"thread_id": 7}],
        "findings": [
            {"severity": "critical", "confidence": "high", "evidence_score": 95, "indicator": "triggerbot", "detector": "RuntimeCorrelationDetector", "explanation": "correlated", "path": "mod.jar"},
            {"severity": "medium", "confidence": "low", "evidence_score": 20, "indicator": "freecam", "detector": "RestrictedModDetector", "explanation": "memory only", "address": "0x1"},
        ],
    }]

    html = _summary_html(summary)

    assert "Strong / correlated evidence" in html
    assert "Weak memory or path signals" in html
    assert "Evidence: 95/100" in html
    assert "Read success" in html
    assert "Runtime class → source JAR" in html
    assert "com.example.TriggerBot" in html
    assert "PE candidates: 1" in html
