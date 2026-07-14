from __future__ import annotations

import json
from pathlib import Path

from .models import ScanSummary


def write_json_summary(summary: ScanSummary, txt_path: Path) -> Path | None:
    path = txt_path.with_suffix(".json")
    try:
        payload = {
            "generated_at": summary.generated_at.isoformat(),
            "overall_status": _overall_status(summary),
            "counts": {
                "jar_scanned": len(summary.jar_results),
                "jar_suspicious": len(summary.suspicious_jars),
                "jar_modrinth_verified": sum(1 for item in summary.jar_results if item.modrinth_verified),
                "pe_analyzed": len(summary.exe_summary.results),
                "static_findings": len(summary.static_results),
                "review_items": len(summary.exe_summary.review_items) + sum(1 for item in summary.static_results if item.review),
                "java_processes_scanned": len(summary.process_results),
                "java_process_findings": sum(len(item.get("findings", [])) for item in summary.process_results),
                "mousetweaks_traces": len(summary.mousetweaks_findings),
                "freecam_traces": len(summary.freecam_findings),
                "autoclicker_traces": len(summary.autoclicker_findings),
                "deleted_mod_traces": len(summary.deleted_mod_findings),
            },
            "top_jar_findings": [
                {"file": item.file_name, "verdict": item.verdict, "score": item.risk_score, "path": str(item.path)}
                for item in sorted(summary.suspicious_jars, key=lambda value: value.risk_score, reverse=True)[:10]
            ],
            "modrinth_verified_jars": [
                {
                    "file": item.file_name,
                    "path": str(item.path),
                    "sha256": item.sha256,
                    "project_id": item.modrinth_project_id,
                    "version_id": item.modrinth_version_id,
                    "version_number": item.modrinth_version_number,
                    "project_url": item.modrinth_project_url,
                }
                for item in summary.jar_results
                if item.modrinth_verified
            ],
            "top_exe_findings": [
                {"file": item.file_name, "verdict": item.verdict, "score": item.risk_score, "path": str(item.path)}
                for item in sorted(summary.exe_summary.review_items, key=lambda value: value.risk_score, reverse=True)[:10]
            ],
            "top_other_findings": [
                {"file": item.file_name, "type": item.file_type, "verdict": item.verdict, "score": item.risk_score, "path": str(item.path)}
                for item in sorted([item for item in summary.static_results if item.review], key=lambda value: value.risk_score, reverse=True)[:10]
            ],
            "grouped_findings": summary.grouped_findings,
            "java_process_results": summary.process_results,
            "mousetweaks_findings": summary.mousetweaks_findings,
            "freecam_findings": summary.freecam_findings,
            "autoclicker_findings": summary.autoclicker_findings,
            "deleted_mod_findings": summary.deleted_mod_findings,
            "change_summary": summary.change_summary.__dict__,
            "scan_health": summary.scan_health.__dict__,
            "report_txt_path": str(txt_path),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        summary.json_report_path = path
        return path
    except OSError:
        return None


def _overall_status(summary: ScanSummary) -> str:
    jar_verdicts = {item.verdict for item in summary.jar_results}
    exe_verdicts = {item.verdict for item in summary.exe_summary.results}
    static_verdicts = {item.verdict for item in summary.static_results}
    process_severities = {str(finding.get("severity", "")).lower() for process in summary.process_results for finding in list(process.get("findings", []) or [])}
    if "critical" in process_severities or jar_verdicts.intersection({"CRITICAL", "HIGH_RISK"}) or exe_verdicts.intersection({"HIGH_REVIEW", "CRITICAL_REVIEW"}) or static_verdicts.intersection({"HIGH_REVIEW", "CRITICAL_REVIEW"}):
        return "HIGH_REVIEW"
    if "high" in process_severities or jar_verdicts.intersection({"SUSPICIOUS", "LOW_SIGNAL"}) or exe_verdicts.intersection({"REVIEW", "LOW_SIGNAL"}) or static_verdicts.intersection({"REVIEW", "LOW_SIGNAL"}):
        return "REVIEW_NEEDED"
    return "CLEAN"
