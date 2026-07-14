from __future__ import annotations

from collections import Counter
from pathlib import Path

from .explain import report_reason
from .models import ExecutableScanResult, JarScanResult, ScanSummary
from .utils import unique_report_path


SOURCE_LABELS = {
    "access_widener": "access_widener_match",
    "config": "config_match",
    "filename": "filename_match",
    "graph": "graph_match",
    "hash": "hash_match",
    "manifest": "metadata_match",
    "metadata": "metadata_match",
    "class_path": "class_path_match",
    "mixin": "mixin_match",
    "nested": "nested_match",
    "resource": "resource_match",
    "correlation": "correlation_match",
    "service": "service_entry_match",
    "string": "string_match",
    "translation": "translation_match",
    "heuristic": "heuristic_match",
    "annotation_attribute": "annotation_attribute_match",
    "bootstrap_method": "bootstrap_method_match",
    "dependency": "dependency_match",
    "descriptor": "descriptor_match",
    "inner_class_attribute": "inner_class_attribute_match",
    "local_variable_table": "local_variable_match",
    "numeric": "numeric_context",
    "opcode": "opcode_shape",
    "ownership": "package_ownership",
    "reachability": "reachability_match",
    "signature": "signature_integrity",
    "source_file_attribute": "source_file_match",
    "vector": "token_vector",
    "version": "version_match",
    "zip": "zip_structure",
}


def write_report(summary: ScanSummary, reports_dir: Path) -> Path:
    path = summary.report_path or unique_report_path(reports_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = render_report(summary)
    path.write_text(text, encoding="utf-8")
    summary.report_path = path
    return path


def render_report(summary: ScanSummary) -> str:
    status = _overall_status(summary)
    suspicious = sorted(summary.suspicious_jars, key=lambda item: item.risk_score, reverse=True)
    exe_results = summary.exe_summary.results or list(summary.executable_results)
    static_review = sorted([item for item in summary.static_results if item.review], key=lambda item: item.risk_score, reverse=True)
    suspicious_executables = sorted(
        [item for item in exe_results if item.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW", "SUSPICIOUS", "HIGH_RISK", "CRITICAL"}],
        key=lambda item: item.risk_score,
        reverse=True,
    )
    low_signal = summary.low_signal_jars
    clean = summary.clean_jars
    modrinth_verified = [item for item in summary.jar_results if item.modrinth_verified]
    duration = max(0, int((summary.generated_at - summary.started_at).total_seconds()))
    review_total = len(suspicious) + len(suspicious_executables) + len(static_review)
    lines: list[str] = []

    lines.append("=" * 60)
    lines.append("VEYRA SCAN - FULL SCAN RESULT")
    lines.append("=" * 60)
    lines.append(f"Overall Status : {status}")
    lines.append(f"Generated      : {summary.generated_at:%Y-%m-%d %H:%M:%S}")
    lines.append(f"Scan Duration  : {duration}s")
    lines.append(f"Minecraft Jars : {summary.scanned_jars} scanned, {len(suspicious)} suspicious")
    lines.append(f"Modrinth Verified: {len(modrinth_verified)} (local analysis retained)")
    lines.append(f"Windows Applications: {len(exe_results)} analyzed, {len(suspicious_executables)} review items")
    lines.append(f"Other Files    : {len(summary.static_results)} analyzed, {len(static_review)} review items")
    lines.append(f"Review Items   : {review_total}")
    lines.append("Report Type    : Local file integrity and content review")
    if summary.completed_categories:
        lines.append("Completed      : " + ", ".join(_category_title(item) for item in summary.completed_categories))
    if summary.not_completed_categories:
        lines.append("Not completed  : " + ", ".join(_category_title(item) for item in summary.not_completed_categories))
    lines.append("")


    lines.append("XRAY / AUTOCLICKER / AUTO-TOTEM / MACE-SWAP FINDER")
    lines.append("-" * 60)
    if not summary.autoclicker_findings:
        lines.append("No Xray, visibility, AutoClicker, Auto-Totem, or Mace-Swap/Swap Helper traces were found in logs, mods, or texture packs.")
    else:
        lines.append(f"ALERT: {len(summary.autoclicker_findings)} Xray/Clicker/Totem/Mace trace(s) found.")
        for item in summary.autoclicker_findings[:50]:
            source = "INSTANCE LOG" if item.get("source_type") == "log" else "MOD FILE"
            line = f" | Line {item.get('line')}" if item.get("line") else ""
            lines.append(f"- [{source}]{line} {item.get('path', '')}")
            lines.append(f"  Evidence: {item.get('evidence', '')}")
            lines.append(f"  Meaning: {item.get('message', 'Xray/AutoClicker trace found.')}")
    lines.append("")

    lines.append("FREECAM FINDER")
    lines.append("-" * 60)
    if not summary.freecam_findings:
        lines.append("No Freecam or FreeLook traces were found in instance logs or scanned mod contents.")
    else:
        lines.append(f"ALERT: {len(summary.freecam_findings)} Freecam/FreeLook trace(s) found.")
        for item in summary.freecam_findings[:50]:
            source = "INSTANCE LOG" if item.get("source_type") == "log" else "MOD FILE"
            line = f" | Line {item.get('line')}" if item.get("line") else ""
            lines.append(f"- [{source}]{line} {item.get('path', '')}")
            lines.append(f"  Evidence: {item.get('evidence', '')}")
            lines.append(f"  Meaning: {item.get('message', 'Freecam/FreeLook trace found.')}")
    lines.append("")
    if summary.category_summaries:
        lines.append("CATEGORY SUMMARIES")
        lines.append("-" * 60)
        for key, value in summary.category_summaries.items():
            lines.append(f"{_category_title(key)}: {value}")
        lines.append("")

    lines.append("CHANGE SUMMARY")
    lines.append("-" * 60)
    lines.append(f"New files: {summary.change_summary.new_application_files + summary.new_jars}")
    lines.append(f"Changed files: {summary.change_summary.changed_known_files + summary.changed_jars}")
    lines.append(f"Same hash different path/name: {summary.change_summary.same_hash_different_names + summary.renamed_or_similar_jars}")
    lines.append(f"New review items: {summary.change_summary.new_review_items}")
    if summary.changed_jars:
        changed_names = [item.file_name for item in summary.jar_results if item.previous_scan_notes and any("changed" in note for note in item.previous_scan_notes)]
        lines.append("Hash-changed jars: " + (", ".join(changed_names[:20]) or "see JSON report"))
    lines.append("")

    lines.append("MOUSETWEAKS FINDER")
    lines.append("-" * 60)
    if not summary.mousetweaks_findings:
        lines.append("No MouseTweaks traces were found in instance logs or scanned mod contents.")
    else:
        lines.append(f"ALERT: {len(summary.mousetweaks_findings)} MouseTweaks trace(s) found.")
        for item in summary.mousetweaks_findings[:50]:
            source = "INSTANCE LOG" if item.get("source_type") == "log" else "MOD FILE"
            instance = item.get("instance") or "Unknown instance"
            line = f" | Line {item.get('line')}" if item.get("line") else ""
            lines.append(f"- [{source}] {instance}{line}")
            lines.append(f"  Path: {item.get('path', '')}")
            lines.append(f"  Evidence: {item.get('evidence', '')}")
        if len(summary.mousetweaks_findings) > 50:
            lines.append(f"+{len(summary.mousetweaks_findings) - 50} more traces in the JSON report")
    lines.append("")

    lines.append("MINECRAFT JAR FINDINGS")
    lines.append("-" * 60)
    lines.append(f"Scanned Jars       : {summary.scanned_jars}")
    lines.append(f"Suspicious Jars    : {len(suspicious)}")
    lines.append(f"Suspicious Jars: {len(suspicious)}")
    lines.append(f"Modrinth verified : {len(modrinth_verified)}")
    lines.append(f"New jars           : {summary.new_jars}")
    lines.append(f"Changed jars       : {summary.changed_jars}")
    lines.append(f"Renamed/similar    : {summary.renamed_or_similar_jars}")
    if summary.analysis_coverage and summary.analysis_coverage != "Unknown":
        lines.append(f"Analysis Coverage  : {summary.analysis_coverage}")
    lines.append("")
    if suspicious:
        high = [item for item in suspicious if item.verdict in {"CRITICAL", "HIGH_RISK"}]
        mismatch = [
            item
            for item in suspicious
            if item not in high and (item.renamed_suspicious or item.non_standard_archive or item.correlation_notes or item.previous_scan_notes)
        ]
        remaining = [item for item in suspicious if item not in high and item not in mismatch]
        ordered = high + mismatch + remaining
        for index, item in enumerate(ordered[:10], 1):
            lines.extend(_render_suspicious_item(index, item))
            lines.append("")
        if len(suspicious) > 10:
            lines.append(f"+{len(suspicious) - 10} more Minecraft jar findings")
            lines.append("")
    else:
        lines.append("No suspicious Minecraft jar indicators found.")
        lines.append("")
    if modrinth_verified:
        lines.append("MODRINTH IDENTITY (LOCAL ANALYSIS RETAINED)")
        for item in modrinth_verified[:20]:
            version = item.modrinth_version_number or item.modrinth_version_name or item.modrinth_version_id
            lines.append(f"- {item.file_name}" + (f" | {version}" if version else ""))
            lines.append(f"  Project: {item.modrinth_project_url}")
        if len(modrinth_verified) > 20:
            lines.append(f"+{len(modrinth_verified) - 20} more Modrinth-verified jars")
        lines.append("")

    lines.append("REMOVED MOD TRACES")
    lines.append("-" * 60)
    if not summary.deleted_mod_findings:
        lines.append("No historical missing-mod JAR/config traces were found.")
    else:
        for finding in summary.deleted_mod_findings[:30]:
            line = f" | line {finding.get('line')}" if finding.get("line") else ""
            lines.append(f"- [{str(finding.get('confidence', 'low')).upper()}] {finding.get('mod_name')} | {finding.get('path')}{line}")
            lines.append(f"  {finding.get('message')} Evidence: {finding.get('evidence')}")
    lines.append("")

    lines.append("LIVE JAVA PROCESS / MEMORY FINDINGS")
    lines.append("-" * 60)
    if not summary.process_results:
        lines.append("No active javaw.exe process was available for live scanning.")
        lines.append("")
    else:
        for process in summary.process_results:
            findings = list(process.get("findings", []) or [])
            lines.append(f"PID {process.get('pid')} | {process.get('process_name', 'javaw.exe')} | Regions: {process.get('scanned_regions', 0)} | Bytes: {process.get('scanned_bytes', 0)}")
            lines.append(f"Modules: {process.get('modules_seen', 0)} | Open files/maps: {process.get('open_files_seen', 0)} | JAR artifacts: {process.get('jar_artifacts_seen', 0)} | JVM args inspected: {process.get('jvm_arguments_seen', 0)} | Admin: {process.get('admin', False)}")
            lines.append(f"Module integrity: {process.get('module_integrity_checked', 0)} PE images checked / {process.get('module_disk_mismatches', 0)} mismatch(es) | Loaded JAR structural probes: {process.get('runtime_jars_probed', 0)}")
            lines.append(f"Parent: {process.get('parent_process_name') or 'unknown'} | Started: {process.get('process_started_at') or 'unknown'} | Threads: {process.get('thread_count', 0)} | Memory stop: {process.get('memory_scan_stop_reason') or 'completed'} | Class-path hints: {process.get('memory_class_hints_seen', 0)}")
            lines.append(f"Memory coverage: {process.get('memory_coverage_quality') or 'Unavailable'} | Mode: {process.get('memory_sampling_mode') or 'unknown'} | Chunks: {process.get('memory_completed_chunks', 0)}/{process.get('memory_planned_chunks', 0)} | Successful regions: {process.get('successful_regions', 0)}/{process.get('scanned_regions', 0)} | Read success: {process.get('memory_read_success_percent', 0)}% | Partial reads: {process.get('memory_partial_reads', 0)} | Working set: {process.get('working_set_bytes', 0)} bytes")
            lines.append(f"Runtime class origins: {process.get('attributed_classes_seen', 0)} | Private executable regions: {process.get('private_executable_regions', 0)} ({process.get('private_executable_bytes', 0)} bytes) | Private PE candidates: {len(process.get('hidden_pe_regions', []) or [])} | Private thread starts: {len(process.get('private_exec_thread_starts', []) or [])} | Unlisted images: {len(process.get('unlisted_image_regions', []) or [])}")
            runtime_only = list(process.get("runtime_only_jars", []) or [])
            memory_jars = list(process.get("memory_jar_paths", []) or [])
            runtime_details = {str(item.get("path", "")): item for item in list(process.get("runtime_jar_details", []) or [])}
            lines.append(f"Disk-memory JAR comparison: {len(memory_jars)} memory path(s), {len(runtime_only)} runtime-only candidate(s)")
            for path in runtime_only[:20]:
                detail = runtime_details.get(str(path), {})
                sources = ", ".join(str(value) for value in detail.get("sources", []) or [])
                digest = str(detail.get("sha256", "") or "")
                lines.append(f"- Runtime-only: {path}" + (f" | source: {sources}" if sources else "") + (f" | SHA-256: {digest}" if digest else ""))
            class_origins = list(process.get("runtime_class_origins", []) or [])
            for origin in class_origins[:30]:
                disk_state = origin.get("class_present_on_disk")
                state = "verified" if disk_state is True else "mismatch" if disk_state is False else "memory-only"
                lines.append(f"- Class origin [{state}]: {origin.get('class_name')} -> {origin.get('jar_path')}!/{origin.get('class_entry')} | {origin.get('address')}")
            if len(class_origins) > 30:
                lines.append(f"+{len(class_origins) - 30} more runtime class origins in JSON report")
            if findings:
                for finding in findings[:20]:
                    location = finding.get("path") or finding.get("address") or ""
                    lines.append(f"- [{str(finding.get('severity', 'info')).upper()} / {str(finding.get('confidence', 'medium')).upper()} CONFIDENCE / EVIDENCE {finding.get('evidence_score', 0)}/100] {finding.get('detector')}: {finding.get('indicator')}" + (f" | {location}" if location else ""))
                    if finding.get("memory_type") or finding.get("protection"):
                        lines.append(f"  Memory region: {finding.get('memory_type', 'unknown')} {finding.get('protection', '')} | base {finding.get('region_base', '')}")
                    if finding.get("explanation"):
                        lines.append(f"  {finding.get('explanation')}")
                if len(findings) > 20:
                    lines.append(f"+{len(findings) - 20} more process findings in JSON report")
            else:
                lines.append("- No configured memory, module, or open-file indicators matched.")
            for note in list(process.get("notes", []) or [])[:4]:
                lines.append(f"- Note: {note}")
            lines.append("")

    lines.append("WINDOWS APPLICATION FINDINGS")
    lines.append("-" * 60)
    exe_summary = summary.exe_summary
    lines.append(f"Inventory PE Files: {summary.inventory_result.count_type('PE_EXE', 'PE_DLL', 'PE_SCR', 'PE_CPL', 'PE_SYS', 'PE_OCX')}")
    lines.append(f"Analyzed PE Files : {len(exe_results)}")
    lines.append(f"Scanned EXEs      : {summary.inventory_result.count_type('PE_EXE') or len(exe_results)}")
    lines.append(f"Review Items      : {len(suspicious_executables)}")
    lines.append(f"High Review       : {len([item for item in suspicious_executables if item.verdict in {'HIGH_REVIEW', 'CRITICAL_REVIEW'}])}")
    lines.append(f"Critical Review   : {len([item for item in suspicious_executables if item.verdict == 'CRITICAL_REVIEW'])}")
    lines.append(f"Unsigned in User Folders: {exe_summary.unsigned_user_folder_count if exe_summary.results else 0}")
    lines.append(f"New Since Last Scan: {exe_summary.new_since_last_scan}")
    lines.append(f"Duplicate EXEs    : {exe_summary.duplicate_hashes or exe_summary.same_hash_different_path}")
    lines.append(f"Skipped Folders   : {exe_summary.stats.skipped_folders}")
    lines.append("")
    lines.append("TOP EXE REVIEW ITEMS")
    lines.append("-" * 60)
    if suspicious_executables:
        for index, item in enumerate(suspicious_executables[:10], 1):
            lines.extend(_render_executable_item(index, item))
            lines.append("")
        if len(suspicious_executables) > 10:
            lines.append(f"+{len(suspicious_executables) - 10} more review items")
            lines.append("")
    else:
        lines.append("No Windows executable review items found.")
        lines.append("")

    lines.append("OTHER STATIC FILE FINDINGS")
    lines.append("-" * 60)
    lines.append(f"Scripts analyzed  : {sum(1 for item in summary.static_results if item.file_type.startswith('SCRIPT'))}")
    lines.append(f"Shortcuts analyzed: {sum(1 for item in summary.static_results if item.file_type.startswith('SHORTCUT'))}")
    lines.append(f"Installers analyzed: {sum(1 for item in summary.static_results if item.file_type.startswith('INSTALLER'))}")
    lines.append(f"Archives analyzed : {sum(1 for item in summary.static_results if item.file_type.startswith('ARCHIVE'))}")
    lines.append(f"Static review items: {len(static_review)}")
    lines.append("")
    for index, item in enumerate(static_review[:10], 1):
        lines.extend(_render_static_item(index, item))
        lines.append("")
    if len(static_review) > 10:
        lines.append(f"+{len(static_review) - 10} more static review items")
        lines.append("")

    lines.append("SUMMARY")
    lines.append("-" * 60)
    lines.append(f"Clean jars: {len(clean)}")
    lines.append(f"Low signal jars: {len(low_signal)}")
    unreadable = [item for item in summary.jar_results if item.error]
    if unreadable:
        lines.append(f"Unreadable jars: {len(unreadable)}")
    lines.append(f"EXE cache hits: {exe_summary.cache_hits}")
    lines.append(f"EXE cache misses: {exe_summary.cache_misses}")
    lines.append(f"EXE elapsed seconds: {exe_summary.elapsed_seconds}")
    lines.append(f"Launcher/mod folders found: {len(summary.locations)}")
    lines.append(f"Official version jars noted: {len(summary.official_version_jars)}")
    lines.append("")

    if summary.grouped_findings:
        lines.append("GROUPED FINDINGS")
        lines.append("-" * 60)
        for name, count in summary.grouped_findings.items():
            if count:
                lines.append(f"{name}: {count}")
        lines.append("")

    health = summary.scan_health
    lines.append("SCAN HEALTH")
    lines.append("-" * 60)
    lines.append(f"Skipped folders: {health.skipped_folders}")
    lines.append(f"Unreadable files: {health.unreadable_files}")
    lines.append(f"Invalid archives: {health.invalid_archives}")
    lines.append(f"Invalid PE files: {health.invalid_pe_files}")
    lines.append(f"Partial analysis: {health.partial_analysis_items}")
    lines.append(f"Signature unknown: {health.signature_check_unknown}")
    lines.append(f"Recovered errors: {health.recovered_errors}")
    lines.append("")

    changes = [*summary.important_changes, *summary.exe_summary.important_changes]
    if changes:
        lines.append("RECENT / RELATED CHANGES")
        lines.append("-" * 60)
        for item in changes[:10]:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("TOP MATCHES")
    lines.append("-" * 60)
    top_lines = _top_matches(summary.jar_results)
    if top_lines:
        lines.extend(top_lines[:15])
    else:
        lines.append("- No high-confidence class/string indicators.")
    lines.append("")

    if unreadable or summary.skipped_errors or summary.exe_summary.stats.discovery_notes:
        lines.append("ACCESS NOTES")
        lines.append("-" * 60)
        for item in unreadable[:5]:
            lines.append(f"- {item.file_name} | UNREADABLE | {item.error}")
        for error in summary.skipped_errors[:5]:
            lines.append(f"- Discovery note: {error}")
        for note in summary.exe_summary.stats.discovery_notes[:5]:
            lines.append(f"- EXE discovery note: {note}")
        lines.append("")

    lines.append("NOTE")
    lines.append("-" * 60)
    lines.append("This scan checks Minecraft .jar contents and local Windows executable inventory/static metadata.")
    lines.append("It does not collect tokens, passwords, browser history, private files, or memory dumps.")
    lines.append("Executable checks use local PE metadata, strings, hashes, sections, imports, and Authenticode status.")
    lines.append("Findings are review indicators, not definitive proof of cheating or malware.")
    lines.append("")
    return "\n".join(lines)


def _render_suspicious_item(index: int, item: JarScanResult) -> list[str]:
    reason = _short_reason(item)
    lines = [
        f"{index}) {item.file_name}",
        f"   Verdict : {item.verdict}",
        f"   Score   : {item.risk_score}/100",
        f"   Confidence: {item.analysis_confidence}",
        f"   Priority: {item.review_priority}" + (f" - {item.review_priority_reason}" if item.review_priority_reason else ""),
        f"   Analysis: {item.analysis_status.replace('_', ' ').title()}",
        f"   Reason  : {reason}",
    ]
    if item.instance_context:
        lines.append(f"   Instance: {item.instance_context}")
    if item.non_standard_archive:
        lines.append("   Archive Type: Java archive with non-standard extension")
    if item.java_agent_manifest:
        capabilities = ", ".join(
            name
            for enabled, name in (
                (item.java_agent_retransform, "retransform"),
                (item.java_agent_redefine, "redefine"),
                (item.java_agent_native_prefix, "native-prefix"),
            )
            if enabled
        )
        lines.append("   Java Agent: manifest entrypoint" + (f" | {capabilities}" if capabilities else ""))
    if item.nested_path:
        lines.append(f"   Nested: {item.nested_path}")
    if item.family_id:
        lines.append(f"   Related group: {item.family_id}" + (f" ({item.family_similarity:.0%})" if item.family_similarity else ""))
    if item.opaque_payload_paths:
        lines.append(
            f"   Opaque payloads: {len(item.opaque_payload_paths)} / {item.opaque_payload_bytes} bytes | "
            f"high entropy={item.opaque_payload_high_entropy}, zero-filled={item.opaque_payload_zero_filled}"
        )
        if item.opaque_payload_formats:
            lines.append("   Hidden executable formats: " + ", ".join(
                f"{path}={payload_format}" for path, payload_format in list(item.opaque_payload_formats.items())[:8]
            ))
    why = item.why_flagged or item.risk_reasons[:3]
    if why:
        lines.append("   Why:")
        for reason_line in why[:3]:
            lines.append(f"   - {reason_line}")
    locations = [
        f"{match.class_name}{('#' + match.method_name) if match.method_name else ''}"
        for match in item.detections
        if match.class_name
    ]
    if locations:
        lines.append("   Locations: " + ", ".join(dict.fromkeys(locations))[:500])
    lines.append(f"   Obfuscation: {item.obfuscation_ratio:.1%} short classes | decoded strings: {len(item.decoded_string_hits)}")
    if item.decoder_signals:
        lines.append("   Decoder signals: " + ", ".join(dict.fromkeys(item.decoder_signals))[:300])
    evidence = _evidence_lines(item)
    for line in evidence[:3]:
        lines.append(f"   Evidence: {line}")
    if item.nested_results:
        suspicious_nested = [child for child in item.nested_results if child.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}]
        for child in suspicious_nested[:2]:
            lines.append(f"   Nested: {child.nested_path} | {child.verdict} {child.risk_score}/100")
    if item.related_files:
        lines.append("   Related Files: " + ", ".join(item.related_files[:4]))
    if item.allowlisted:
        lines.append(f"   Allowlist: matched ({', '.join(item.allowlist_notes)})")
    if item.known_hash_status:
        lines.append(f"   LocalHash: {item.known_hash_status}")
    if item.deep_audit_entries:
        lines.append(f"   Deep audit: {item.deep_audit_entries} entries / {item.deep_audit_bytes} bytes streamed")
        lines.append(f"   Payload digest: {item.deep_audit_sha256}")
        lines.append(
            "   Structure: "
            f"classes={item.deep_audit_class_entries} valid={item.deep_audit_valid_class_entries} "
            f"invalid={item.deep_audit_invalid_class_entries}, nested={item.deep_audit_nested_archives}, "
            f"encrypted={item.deep_audit_encrypted_entries}, suspicious paths={item.deep_audit_suspicious_paths}, "
            f"max compression={item.deep_audit_max_compression_ratio:.1f}x, "
            f"high entropy={item.deep_audit_high_entropy_entries} (max {item.deep_audit_max_entropy:.2f})"
        )
        if item.deep_audit_high_compression_entries or item.deep_audit_duplicate_hashes or item.deep_audit_embedded_native or item.deep_audit_crc_error:
            lines.append(f"   Archive anomalies: compression={item.deep_audit_high_compression_entries}, duplicates={item.deep_audit_duplicate_hashes}, embedded executable/script={item.deep_audit_embedded_native}, CRC={item.deep_audit_crc_error or 'OK'}")
        if item.deep_audit_feature_hits:
            lines.append("   Deep feature strings: " + "; ".join(item.deep_audit_feature_hits[:8])[:500])
    lines.append(f"   Path    : {item.path}")
    return lines


def _render_executable_item(index: int, item: ExecutableScanResult) -> list[str]:
    indicators = ", ".join(getattr(item, "matched_indicators", [])[:6]) if hasattr(item, "matched_indicators") else ""
    reason = " / ".join(getattr(item, "reasons", [])[:2]) if getattr(item, "reasons", None) else "Windows executable review indicators."
    evidence = list(getattr(item, "evidence", []) or [])
    if not evidence and indicators:
        evidence.append(f"indicators: {indicators}")
    lines = [
        f"{index}) {item.file_name}",
        f"   File Type: {getattr(item, 'file_type', 'PE_EXE')}",
        f"   Verdict : {item.verdict}",
        f"   Score   : {item.risk_score}/100",
        f"   Priority: {getattr(item, 'review_priority', 'NORMAL')}" + (f" - {getattr(item, 'review_priority_reason', '')}" if getattr(item, "review_priority_reason", "") else ""),
        f"   Confidence: {getattr(item, 'confidence', 'LOW')}",
        f"   Reason  : {reason}",
    ]
    for line in evidence[:3]:
        lines.append(f"   Evidence: {line}")
    lines.append(f"   Signature: {getattr(item, 'signature_status', 'UNKNOWN')}")
    lines.append(f"   Path    : {item.path}")
    return lines


def _render_static_item(index: int, item) -> list[str]:
    lines = [
        f"{index}) {item.file_name}",
        f"   File Type: {item.file_type}",
        f"   Verdict : {item.verdict}",
        f"   Score   : {item.risk_score}/100",
        f"   Priority: {item.priority}",
        f"   Confidence: {item.confidence}",
        f"   Reason  : {' / '.join(item.reasons[:2]) if item.reasons else 'Static review indicator.'}",
    ]
    for evidence in item.evidence[:3]:
        lines.append(f"   Evidence: {evidence}")
    if item.target_path:
        lines.append(f"   Target  : {item.target_path}")
    if item.nested_items:
        lines.append(f"   Nested Item: {item.nested_items[0]}")
    lines.append(f"   Path    : {item.path}")
    return lines


def _short_reason(item: JarScanResult) -> str:
    if item.error:
        return item.error
    explained = report_reason(item)
    if explained != "No direct rule match.":
        return explained
    detections = _unique_rule_matches(sorted(item.detections, key=_report_detection_key))
    strong = [d for d in detections if d.severity in {"critical", "high"}]
    picked = strong[:3] if strong else detections[:3]
    if not picked:
        return "No direct rule match."
    names = " / ".join(dict.fromkeys(d.rule_name.replace(" indicators", "") for d in picked))
    if item.renamed_suspicious:
        return f"File name looks normal but internals contain {names}"
    return f"{names} found in jar content"


def _evidence_lines(item: JarScanResult) -> list[str]:
    lines = []
    for match in _unique_rule_matches(sorted(item.detections, key=_evidence_quality, reverse=True)):
        if match.severity not in {"critical", "high", "medium"}:
            continue
        source_label = SOURCE_LABELS.get(match.source_type, f"{match.source_type}_match")
        if match.source_type == "string":
            lines.append(f'{source_label}: string contains "{match.matched_keyword}" | {match.evidence_preview}')
        else:
            lines.append(f"{source_label}: {match.evidence_preview}")
    return lines


def _unique_rule_matches(matches):
    out = []
    seen = set()
    for match in matches:
        if match.rule_id in seen:
            continue
        seen.add(match.rule_id)
        out.append(match)
    return out


def _report_detection_key(match):
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    source_order = {
        "class_path": 0,
        "string": 1,
        "config": 2,
        "translation": 3,
        "mixin": 4,
        "graph": 5,
        "nested": 6,
        "metadata": 7,
        "manifest": 8,
        "filename": 9,
        "heuristic": 10,
    }
    return (
        severity_order.get(match.severity, 9),
        source_order.get(match.source_type, 9),
        match.category,
        match.rule_name,
    )


def _evidence_quality(match) -> tuple[int, int, int, int, str]:
    severity_points = {"critical": 100, "high": 80, "medium": 55, "low": 20, "info": 0}
    source_points = {
        "ownership": 24,
        "reachability": 24,
        "class_path": 22,
        "mixin": 22,
        "source_file_attribute": 21,
        "descriptor": 20,
        "string": 19,
        "config": 19,
        "translation": 19,
        "graph": 18,
        "numeric": 16,
        "opcode": 16,
        "vector": 13,
        "metadata": 10,
        "manifest": 8,
        "filename": 4,
    }
    readable = 0 if len(match.evidence_preview) > 170 else 10
    context = 8 if match.context_type in {"class_graph", "mixin_target", "translation_key", "config_key", "debug_attribute", "numeric_context"} else 0
    weak_noise = -25 if match.rule_id in {"RANDOM_LOOKING_FILENAME", "MISSING_METADATA_SUPPORT_SIGNAL", "ZIP_STRUCTURE_ANOMALY"} else 0
    return (
        severity_points.get(match.severity, 0) + source_points.get(match.source_type, 0) + readable + context + weak_noise,
        source_points.get(match.source_type, 0),
        readable,
        context,
        match.rule_name,
    )


def _top_matches(results: list[JarScanResult]) -> list[str]:
    counter: Counter[str] = Counter()
    examples: dict[str, str] = {}
    for item in results:
        for match in item.detections:
            if match.severity not in {"critical", "high"}:
                continue
            key = f"{match.rule_name} ({SOURCE_LABELS.get(match.source_type, match.source_type)})"
            counter[key] += 1
            examples.setdefault(key, item.file_name)
    out = []
    for key, count in counter.most_common(15):
        out.append(f"- {key}: {count} match(es), example: {examples[key]}")
    return out


def _category_title(category_id: str) -> str:
    titles = {
        "minecraft": "Minecraft Jar Scan",
        "manual_jar": "Manual JAR Deep Scan",
        "javaw_scan": "Javaw Process / Memory Scan",
        "mousetweaks_freecam": "MouseTweaks / Freecam Finder",
        "xray_autoclicker": "Xray / AutoClicker / Auto-Totem / Mace-Swap",
        "quick_windows": "Quick Windows App Review",
        "installed_apps": "Installed Apps Review",
        "other_files": "Other File Review",
    }
    return titles.get(category_id, category_id)


def _overall_status(summary: ScanSummary) -> str:
    jar_verdicts = {item.verdict for item in summary.jar_results}
    exe_results = summary.exe_summary.results or list(summary.executable_results)
    exe_verdicts = {item.verdict for item in exe_results}
    static_verdicts = {item.verdict for item in summary.static_results}
    process_severities = {str(finding.get("severity", "")).lower() for process in summary.process_results for finding in list(process.get("findings", []) or [])}
    if "critical" in process_severities or jar_verdicts.intersection({"CRITICAL", "HIGH_RISK"}) or exe_verdicts.intersection({"HIGH_REVIEW", "CRITICAL_REVIEW"}) or static_verdicts.intersection({"HIGH_REVIEW", "CRITICAL_REVIEW"}):
        return "HIGH_REVIEW"
    if "high" in process_severities or jar_verdicts.intersection({"SUSPICIOUS", "LOW_SIGNAL"}) or exe_verdicts.intersection({"REVIEW", "LOW_SIGNAL"}) or static_verdicts.intersection({"REVIEW", "LOW_SIGNAL"}):
        return "REVIEW_NEEDED"
    return "CLEAN"
