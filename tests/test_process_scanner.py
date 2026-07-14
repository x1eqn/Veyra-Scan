from __future__ import annotations

import datetime as dt
import zipfile

from xien_control.models import ScanSummary
from xien_control.process_scanner import EXECUTABLE_PROTECTIONS, MEM_PRIVATE, GenericModDetector, JavaProcessScanResult, JavaProcessScannerEngine, JvmInjectionDetector, KnownClientMemoryDetector, MemorySignature, ProcessFinding, RestrictedModDetector, _ReadableRegion, _build_memory_scan_plan, _calibrate_process_findings, _class_origin_findings, _compare_runtime_to_disk, _correlate_runtime_findings, _extract_memory_class_origins, _extract_memory_jar_paths, _extract_suspicious_class_hints, _loaded_module_integrity_findings, _looks_like_pe_image, _memory_coverage_quality, _native_memory_findings, _normalize_extracted_jar_path, _runtime_jar_details, _runtime_jar_probe_findings, _thread_private_exec_matches, _verify_class_origins
from xien_control.report_writer import render_report


def test_ascii_and_wildcard_memory_signatures():
    ascii_signature = MemorySignature("A", "Doomsday", "doomsday").compile()
    wildcard_signature = MemorySignature("B", "Wildcard", "48 8B ?? 89", hex_pattern=True).compile()

    assert ascii_signature.search(b"prefix-DOOMSDAY-suffix")
    assert wildcard_signature.search(bytes.fromhex("48 8B FF 89"))


def test_generic_detector_flags_named_artifact_and_temp_dll():
    detector = GenericModDetector()
    findings = detector.analyze_artifacts(
        10,
        "javaw.exe",
        [r"C:\Users\tester\AppData\Local\Temp\overlay.dll"],
        [r"C:\Minecraft\mods\vape-client.jar"],
    )

    assert any(item.indicator in {"vape", "vape client", "vapeclient"} and item.severity == "high" for item in findings)
    assert any(item.finding_type == "unusual_loaded_dll" for item in findings)


def test_java_launcher_native_dlls_are_not_temp_dll_false_flags():
    detector = GenericModDetector()
    findings = detector.analyze_artifacts(
        10,
        "javaw.exe",
        [],
        [
            r"C:\Users\tester\AppData\Local\Temp\lib1093133325135536293.dll",
            r"C:\Users\tester\AppData\Local\Temp\native\player.dll",
        ],
    )
    assert not any(item.finding_type == "unusual_loaded_dll" for item in findings)


def test_engine_returns_empty_when_java_is_not_running(monkeypatch):
    monkeypatch.setattr("xien_control.process_scanner._javaw_processes", lambda: [])
    assert JavaProcessScannerEngine().scan() == []


def test_known_client_memory_detector_supports_ascii_and_utf16():
    signatures = {item.signature_id: item.compile() for item in KnownClientMemoryDetector().signatures()}
    assert signatures["KNOWN_CLIENT_FAMILY_ASCII"].search(b"x-grimclient-y")
    assert signatures["KNOWN_CLIENT_FAMILY_UTF16"].search("x-grimclient-y".encode("utf-16le"))


def test_jvm_agent_arguments_are_reported_with_context():
    findings = JvmInjectionDetector().analyze_artifacts(
        10,
        "javaw.exe",
        [],
        [r"-javaagent:C:\Temp\agent.jar", "-noverify"],
    )
    assert any(item.finding_type == "jvm_agent" and item.severity == "medium" for item in findings)
    assert any(item.finding_type == "verification_disabled" and item.severity == "low" for item in findings)

    known = JvmInjectionDetector().analyze_artifacts(10, "javaw.exe", [], [r"-javaagent:C:\Temp\grimclient-agent.jar"])
    assert any(item.finding_type == "jvm_agent" and item.severity == "high" for item in known)


def test_known_client_family_in_runtime_jar_path_is_detected():
    findings = GenericModDetector().analyze_artifacts(
        10,
        "javaw.exe",
        [],
        [r"C:\Minecraft\mods\tenac1ty-loader.jar"],
    )
    assert any(item.finding_type == "known_client_artifact" and item.indicator == "tenacity" for item in findings)


def test_restricted_mod_detector_covers_totem_freecam_and_mace_swap():
    findings = RestrictedModDetector().analyze_artifacts(
        10,
        "javaw.exe",
        [],
        [
            r"C:\\Minecraft\\mods\\auto-totem-plus.jar",
            r"C:\\Minecraft\\mods\\Freecam.jar",
            r"C:\\Minecraft\\mods\\swap-helper.jar",
        ],
    )
    indicators = {item.indicator for item in findings}
    assert {"Auto-Totem", "Freecam", "Mace/Swap helper"}.issubset(indicators)


def test_mace_swap_memory_signature_is_not_used_without_artifact_context():
    signatures = {item.signature_id for item in RestrictedModDetector().signatures()}
    assert not any("MACESWAP" in item for item in signatures)
    assert any(item.indicator == "Mace/Swap helper" for item in RestrictedModDetector().analyze_artifacts(10, "javaw.exe", [], [r"C:\\Minecraft\\mods\\swap-helper.jar"]))


def test_jvm_loader_overrides_are_reported():
    findings = JvmInjectionDetector().analyze_artifacts(
        10,
        "javaw.exe",
        [],
        ["-Xbootclasspath/a:C:\\Temp\\loader.jar", "-Djava.system.class.loader=com.example.Loader"],
    )
    assert any(item.finding_type == "boot_classpath_override" for item in findings)
    assert any(item.finding_type == "custom_system_class_loader" for item in findings)


def test_java_environment_injection_is_reported():
    findings = JvmInjectionDetector().analyze_artifacts(
        10,
        "javaw.exe",
        [],
        ["JAVA_TOOL_OPTIONS=-javaagent:C:\\Temp\\agent.jar"],
    )
    assert any(item.finding_type == "environment_jvm_injection" and item.severity == "high" for item in findings)


def test_runtime_artifact_and_memory_signals_are_correlated():
    findings = [
        ProcessFinding(10, "javaw.exe", "RestrictedModDetector", "restricted_mod_artifact", "high", "Freecam", path=r"C:\\Minecraft\\mods\\freecam.jar"),
        ProcessFinding(10, "javaw.exe", "RestrictedModDetector", "memory_signature", "high", "Freecam identifier in JVM memory", address="0x1234"),
    ]
    correlated = _correlate_runtime_findings(findings, 10, "javaw.exe")
    assert any(item.finding_type == "artifact_memory_correlation" and item.indicator == "freecam" for item in correlated)


def test_class_hint_extractor_requires_a_class_shaped_path():
    hints = _extract_suspicious_class_hints(b"noise com/example/combat/TriggerBotModule.class tail")

    assert any(family == "triggerbot" and "TriggerBotModule" in path for path, family, _offset in hints)
    assert _extract_suspicious_class_hints(b"a player mentioned triggerbot in chat") == []


def test_memory_only_restricted_word_is_downgraded_without_independent_evidence():
    findings = [
        ProcessFinding(10, "javaw.exe", "RestrictedModDetector", "memory_signature", "high", "Freecam identifier in JVM memory", address="0x1234"),
    ]

    calibrated = _calibrate_process_findings(findings)

    assert calibrated[0].severity == "medium"
    assert calibrated[0].confidence == "low"
    assert calibrated[0].evidence_score == 20
    assert "not proof" in calibrated[0].explanation


def test_correlated_runtime_evidence_is_high_confidence():
    findings = [
        ProcessFinding(10, "javaw.exe", "RestrictedModDetector", "restricted_mod_artifact", "high", "Freecam", path=r"C:\\Minecraft\\mods\\freecam.jar"),
        ProcessFinding(10, "javaw.exe", "RestrictedModDetector", "memory_signature", "high", "Freecam identifier in JVM memory", address="0x1234"),
    ]
    findings.extend(_correlate_runtime_findings(findings, 10, "javaw.exe"))

    calibrated = _calibrate_process_findings(findings)

    assert any(item.finding_type == "artifact_memory_correlation" and item.confidence == "high" for item in calibrated)
    assert any(item.finding_type == "artifact_memory_correlation" and item.evidence_score == 95 for item in calibrated)
    assert any(item.finding_type == "memory_signature" and item.severity == "high" and item.confidence == "high" for item in calibrated)


def test_memory_coverage_quality_distinguishes_complete_limited_and_partial():
    complete = JavaProcessScanResult(
        pid=10, scanned_bytes=1024, scanned_regions=4, successful_regions=4,
        memory_read_attempts=4, memory_read_failures=0, memory_scan_stop_reason="memory map completed",
    )
    limited = JavaProcessScanResult(
        pid=10, scanned_bytes=1024, scanned_regions=4, successful_regions=4,
        memory_read_attempts=4, memory_read_failures=0, memory_scan_stop_reason="time budget reached",
    )
    partial = JavaProcessScanResult(
        pid=10, scanned_bytes=1024, scanned_regions=4, successful_regions=1,
        memory_read_attempts=10, memory_read_failures=5, memory_scan_stop_reason="memory map completed",
    )

    assert _memory_coverage_quality(complete) == "Complete map"
    assert _memory_coverage_quality(limited) == "Limited"
    assert _memory_coverage_quality(partial) == "Partial"


def test_balanced_memory_plan_reaches_low_middle_and_high_addresses():
    megabyte = 1024 * 1024
    regions = [
        _ReadableRegion(0x10000000, 16 * megabyte),
        _ReadableRegion(0x50000000, 16 * megabyte),
        _ReadableRegion(0x90000000, 16 * megabyte),
    ]

    tasks, mode = _build_memory_scan_plan(regions, megabyte, 6 * megabyte)
    addresses = [task.address for task in tasks]

    assert mode == "balanced"
    assert len(tasks) == 6
    assert any(address < 0x20000000 for address in addresses)
    assert any(0x50000000 <= address < 0x60000000 for address in addresses)
    assert any(address >= 0x90000000 for address in addresses)
    assert any(address < 0x20000000 for address in addresses[:3])
    assert any(0x50000000 <= address < 0x60000000 for address in addresses[:3])
    assert any(address >= 0x90000000 for address in addresses[:3])


def test_full_memory_plan_reads_every_chunk_when_budget_allows():
    region = _ReadableRegion(0x1000, 3 * 64 * 1024)

    tasks, mode = _build_memory_scan_plan([region], 64 * 1024, 3 * 64 * 1024)

    assert mode == "full"
    assert [task.address for task in tasks] == [0x1000, 0x11000, 0x21000]


def test_java_classloader_jar_urls_are_normalized_to_windows_paths():
    assert _normalize_extracted_jar_path("jar:file:/C:/Users/Test/My%20Mods/freecam.jar") == "C:/Users/Test/My Mods/freecam.jar"
    paths = _extract_memory_jar_paths(b"jar:file:/C:/Users/Test/My%20Mods/freecam.jar!/com/x/Main.class")
    assert paths == ["C:/Users/Test/My Mods/freecam.jar"]


def test_runtime_class_origin_maps_class_to_jar_and_verifies_disk(tmp_path):
    jar_path = tmp_path / "freecam-helper.jar"
    with zipfile.ZipFile(jar_path, "w") as archive:
        archive.writestr("com/example/FreecamModule.class", b"class")
    uri = f"jar:file:/{str(jar_path).replace(chr(92), '/')}!/com/example/FreecamModule.class".encode()

    origins = _extract_memory_class_origins(uri, base_address=0x1000)
    verified = _verify_class_origins(origins)
    findings = _class_origin_findings(verified, 10, "javaw.exe")

    assert verified[0]["class_name"] == "com.example.FreecamModule"
    assert verified[0]["class_present_on_disk"] is True
    assert verified[0]["address"] == "0x1000"
    assert any(item.finding_type == "class_jar_attribution" for item in findings)


def test_runtime_class_disk_mismatch_is_reported(tmp_path):
    jar_path = tmp_path / "changed.jar"
    with zipfile.ZipFile(jar_path, "w") as archive:
        archive.writestr("com/example/Other.class", b"class")
    origins = [{
        "jar_path": str(jar_path), "class_entry": "com/example/Freecam.class",
        "class_name": "com.example.Freecam", "address": "0x22", "encoding": "latin1",
        "on_disk": False, "class_present_on_disk": None,
    }]

    findings = _class_origin_findings(_verify_class_origins(origins), 10, "javaw.exe")

    assert any(item.finding_type == "runtime_class_disk_mismatch" and item.severity == "high" for item in findings)


def test_valid_pe_header_is_required_for_private_image_detection():
    payload = bytearray(512)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (0x80).to_bytes(4, "little")
    payload[0x80:0x84] = b"PE\x00\x00"

    assert _looks_like_pe_image(bytes(payload)) is True
    payload[0x80:0x84] = b"NOPE"
    assert _looks_like_pe_image(bytes(payload)) is False


def test_manual_map_requires_pe_or_thread_correlation_not_jit_region_alone():
    executable_protection = next(iter(EXECUTABLE_PROTECTIONS))
    region = _ReadableRegion(0x5000, 0x1000, MEM_PRIVATE, 0x5000, executable_protection)

    empty_findings, empty_threads = _native_memory_findings(10, "javaw.exe", [region], set(), set(), [])
    correlated_findings, thread_matches = _native_memory_findings(
        10, "javaw.exe", [region], {0x5000}, set(), [{"thread_id": 7, "start_address": 0x5100}],
    )

    assert empty_findings == []
    assert empty_threads == []
    assert thread_matches[0]["allocation_base"] == 0x5000
    assert any(item.finding_type == "manual_map_correlation" for item in correlated_findings)


def test_private_thread_match_rejects_normal_image_address():
    executable_protection = next(iter(EXECUTABLE_PROTECTIONS))
    region = _ReadableRegion(0x5000, 0x1000, MEM_PRIVATE, 0x5000, executable_protection)
    matches = _thread_private_exec_matches(
        [{"thread_id": 1, "start_address": 0x7000}, {"thread_id": 2, "start_address": 0x5100}],
        [region],
    )
    assert [item["thread_id"] for item in matches] == [2]


def test_memory_jar_path_extraction_and_runtime_only_comparison(tmp_path):
    runtime_path = str(tmp_path / "mods" / "removed-freecam.jar")
    paths = _extract_memory_jar_paths(f"prefix {runtime_path} suffix".encode())
    assert runtime_path in paths

    result = JavaProcessScanResult(pid=10, runtime_jars=paths)
    _compare_runtime_to_disk(result, [])
    assert runtime_path in result.runtime_only_jars
    assert any(item.finding_type == "runtime_only_jar" for item in result.findings)


def test_installed_runtime_jar_is_not_reported_as_runtime_only(tmp_path):
    mods = tmp_path / "mods"
    mods.mkdir()
    path = mods / "freecam.jar"
    path.write_bytes(b"PK")
    result = JavaProcessScanResult(pid=10, runtime_jars=[str(path)])
    _compare_runtime_to_disk(result, [path])
    assert result.runtime_only_jars == []


def test_runtime_jar_provenance_hashes_mod_candidates(tmp_path):
    mods = tmp_path / "mods"
    mods.mkdir()
    path = mods / "freecam.jar"
    path.write_bytes(b"runtime-jar")

    details = _runtime_jar_details([str(path)], [str(path)], [str(path)])

    assert details[0]["exists"] is True
    assert len(str(details[0]["sha256"])) == 64
    assert details[0]["location"] == "mods"
    assert set(details[0]["sources"]) == {"open file / classpath", "JVM memory"}


def test_loaded_runtime_jar_concealed_loader_probe_requires_correlated_structure(tmp_path):
    mods = tmp_path / "mods"
    mods.mkdir()
    path = mods / "renamed-helper.jar"
    high_entropy = bytes(range(256)) * 32
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Premain-Class: x.Agent\nCan-Retransform-Classes: true\n")
        for letter in "abc":
            archive.writestr(f"payload/{letter}", high_entropy)
        archive.writestr("x/Loader.class", b"ClassLoader defineClass")
        archive.writestr("x/Native.class", b"NativeLibrary com/sun/jna/Pointer Runtime exec")
        archive.writestr("x/Transport.class", b"SocketChannel RandomAccessFile getResourceAsStream")
    details = [{"path": str(path), "exists": True, "location": "mods"}]

    findings, probed = _runtime_jar_probe_findings(details, 10, "javaw.exe")

    assert probed == 1
    assert any(item.finding_type == "runtime_concealed_loader" and item.severity == "critical" for item in findings)
    assert details[0]["structural_probe"]["high_entropy_opaque_payloads"] == 3


def test_runtime_probe_does_not_flag_plain_java_agent(tmp_path):
    mods = tmp_path / "mods"
    mods.mkdir()
    path = mods / "profiler.jar"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Premain-Class: profiler.Agent\nCan-Retransform-Classes: true\n")
        archive.writestr("profiler/Agent.class", b"Instrumentation ClassFileTransformer")

    findings, probed = _runtime_jar_probe_findings([{"path": str(path), "exists": True}], 10, "javaw.exe")

    assert probed == 1
    assert findings == []


def test_loaded_module_disk_image_size_mismatch_is_high_confidence(tmp_path):
    path = tmp_path / "overlay.dll"
    payload = bytearray(512)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (0x80).to_bytes(4, "little")
    payload[0x80:0x84] = b"PE\x00\x00"
    payload[0x80 + 24:0x80 + 26] = (0x20B).to_bytes(2, "little")
    payload[0x80 + 24 + 56:0x80 + 24 + 60] = (0x5000).to_bytes(4, "little")
    path.write_bytes(payload)

    findings, checked, mismatches = _loaded_module_integrity_findings(
        [{"path": str(path), "base": 0x100000, "size": 0x9000}], 10, "javaw.exe",
    )

    assert checked == 1
    assert mismatches == 1
    assert any(item.finding_type == "loaded_module_disk_mismatch" and item.confidence == "high" for item in findings)


def test_process_findings_are_rendered_in_report():
    now = dt.datetime(2026, 7, 12, 12, 0, 0)
    summary = ScanSummary(
        started_at=now,
        generated_at=now,
        process_results=[
            {
                "pid": 42,
                "process_name": "javaw.exe",
                "scanned_regions": 12,
                "scanned_bytes": 4096,
                "modules_seen": 8,
                "open_files_seen": 4,
                "admin": True,
                "findings": [{"severity": "critical", "detector": "DoomsdayDetector", "indicator": "Doomsday client name", "address": "0x1234", "explanation": "signature match"}],
                "notes": [],
            }
        ],
    )

    report = render_report(summary)

    assert "LIVE JAVA PROCESS / MEMORY FINDINGS" in report
    assert "PID 42" in report
    assert "DoomsdayDetector" in report
