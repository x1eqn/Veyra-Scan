from __future__ import annotations

import datetime as dt
import os
import time
import sys
import threading
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from .archive_identifier import identify_java_archive, is_java_archive_candidate
from .archive_scanner import ArchiveScanner
from .artifact_db import ArtifactDatabase
from .change_story import ApplicationChangeStory
from .correlation import correlate_results
from .deep_analysis_queue import build_deep_analysis_queue
from .exe_artifacts import ExeArtifactDatabase
from .exe_models import ExeDiscoveryStats, ExeScanResult, ExeScanSummary
from .exe_scanner import WindowsExeScanner
from .file_classifier import is_archive_type, is_installer_type, is_pe_type, is_script_type, is_shortcut_type
from .grouping import grouped_findings
from .installer_analyzer import InstallerAnalyzer
from .inventory import InventoryScanner
from .jar_scanner import JarScanner
from .json_report_writer import write_json_summary
from .launcher_discovery import LauncherDiscovery
from .location_baseline import LocationBaseline
from .models import JarScanResult, LauncherLocation, ScanSummary
from .modrinth_verifier import ModrinthMatch, ModrinthVerifier
from .mousetweaks_finder import MouseTweaksFinder
from .freecam_finder import FreecamFinder
from .autoclicker_finder import AutoClickerFinder
from .deleted_mod_finder import DeletedModTraceFinder
from .parallel_runner import default_worker_count, run_parallel
from .process_scanner import JavaProcessScannerEngine
from .report_writer import write_report
from .risk import calculate_jar_risk
from .scan_health import build_scan_health
from .script_analyzer import ScriptAnalyzer
from .shortcut_analyzer import ShortcutAnalyzer
from .static_models import ChangeSummary, FileInventoryItem, InventoryResult, StaticAnalysisResult
from .utils import now_local, sha256_sha512_file


LogFn = Callable[[str, str], None]
ProgressFn = Callable[[int, int, str], None]
ALL_CATEGORY_IDS = ("minecraft", "manual_jar", "javaw_scan", "mousetweaks_freecam", "xray_autoclicker")


def _scan_jar_process_worker(task):
    """Process-isolated JAR analysis worker for CPU-heavy bytecode parsing."""
    index, jar_path, location, digest, cache_dir, deep_enabled = task
    messages: list[tuple[str, str]] = []
    scanner = JarScanner(
        log=lambda tag, message: messages.append((str(tag), str(message))),
        cache_dir=Path(cache_dir),
        enable_cache=False,
    )
    try:
        result = scanner.scan(Path(jar_path), location, precomputed_sha256=digest)
        if deep_enabled:
            try:
                result = scanner.deep_audit(Path(jar_path), result)
            except (OSError, PermissionError, RuntimeError, zipfile.BadZipFile) as exc:
                messages.append(("WARN", f"Independent archive pass recovered for {Path(jar_path).name}: {exc}"))
        return index, result, messages
    except Exception as exc:  # noqa: BLE001
        return index, _failed_jar_result(Path(jar_path), location, exc), messages


class ScanOrchestrator:
    def __init__(
        self,
        log: LogFn,
        progress: ProgressFn,
        cache_dir: Path | None = None,
        reports_dir: Path | None = None,
        inventory_roots: list[Path] | None = None,
        max_inventory_files: int | None = None,
        enable_launcher_discovery: bool = True,
        manual_jar_paths: list[Path] | None = None,
    ):
        self.log = log
        self.progress = progress
        self.cache_dir = cache_dir or application_root() / "xien_control_cache"
        # GUI reports stay in the app's private data directory; never place
        # scan output in the user's Downloads folder.
        self.reports_dir = reports_dir or report_storage_dir()
        self.inventory_roots = inventory_roots
        self.max_inventory_files = max_inventory_files
        self.enable_launcher_discovery = enable_launcher_discovery
        self.manual_jar_paths = list(manual_jar_paths or [])

    def run(self) -> ScanSummary:
        started = now_local()
        errors: list[str] = []
        locations: list[LauncherLocation] = []
        reference_jars: list[Path] = []
        mousetweaks_findings: list[dict[str, object]] = []

        if self.enable_launcher_discovery:
            self.log("DISCOVERY", "Searching launcher folders...")
            try:
                launcher_discovery = LauncherDiscovery(log=self.log)
                locations, reference_jars, discovery_errors = launcher_discovery.discover()
                errors.extend(discovery_errors)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"launcher discovery recovered error: {exc}")
                self.log("WARN", errors[-1])

        try:
            baseline = LocationBaseline(self.cache_dir)
        except Exception as exc:  # noqa: BLE001
            baseline = None
            errors.append(f"location baseline recovered error: {exc}")
            self.log("WARN", errors[-1])

        try:
            inventory = InventoryScanner(log=self.log, roots=self.inventory_roots, max_files=self.max_inventory_files).scan()
        except Exception as exc:  # noqa: BLE001
            inventory = InventoryResult()
            inventory.stats.errors_recovered += 1
            inventory.stats.notes.append(f"inventory phase recovered error: {exc}")
            errors.append(inventory.stats.notes[-1])
            self.log("WARN", errors[-1])

        try:
            deep_queue = build_deep_analysis_queue(inventory.items, baseline)
        except Exception as exc:  # noqa: BLE001
            deep_queue = build_deep_analysis_queue([], None)
            errors.append(f"deep analysis queue recovered error: {exc}")
            self.log("WARN", errors[-1])
        self.log("SCAN", f"Deep analysis queue: {len(deep_queue.items)} files")
        self.log("WORKER", f"{default_worker_count(len(deep_queue.items))} analysis workers active")

        try:
            jar_targets = self._merge_jar_targets(self._collect_launcher_jars(locations), self._jar_targets_from_inventory(deep_queue.items))
            jar_results = self._scan_jars(jar_targets)
        except Exception as exc:  # noqa: BLE001
            jar_results = []
            errors.append(f"minecraft jar analysis recovered error: {exc}")
            self.log("WARN", errors[-1])
        freecam_findings = self._find_freecam(locations, jar_results, errors)
        autoclicker_findings = self._find_autoclicker(locations, jar_results, errors)
        pe_items = [item for item in deep_queue.items if is_pe_type(item.file_type)]
        static_items = [
            item
            for item in deep_queue.items
            if is_script_type(item.file_type) or is_shortcut_type(item.file_type) or is_installer_type(item.file_type) or is_archive_type(item.file_type)
        ]
        try:
            exe_summary = self._scan_pe_items(pe_items, inventory.stats)
        except Exception as exc:  # noqa: BLE001
            exe_summary = ExeScanSummary(stats=ExeDiscoveryStats(discovery_notes=[f"PE analysis recovered error: {exc}"], errors_recovered=1))
            errors.append(exe_summary.stats.discovery_notes[-1])
            self.log("WARN", errors[-1])
        try:
            static_results = self._scan_static_items(static_items)
        except Exception as exc:  # noqa: BLE001
            static_results = []
            errors.append(f"extra file type analysis recovered error: {exc}")
            self.log("WARN", errors[-1])

        try:
            correlate_results(jar_results)
            for item in jar_results:
                if item.correlation_notes:
                    breakdown = calculate_jar_risk(item)
                    item.risk_score = breakdown.score
                    item.verdict = breakdown.verdict
                    item.risk_reasons = breakdown.reasons
        except Exception as exc:  # noqa: BLE001
            errors.append(f"correlation recovered error: {exc}")
            self.log("WARN", errors[-1])

        jar_diff: dict[str, object] = {"new": 0, "changed": 0, "removed": 0, "renamed_or_similar": 0, "important": []}
        try:
            artifact_db = ArtifactDatabase(self.cache_dir)
            jar_diff = artifact_db.compare_previous(jar_results)
            artifact_db.update(jar_results)
            artifact_db.save()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"jar artifact database recovered error: {exc}")
            self.log("WARN", errors[-1])

        all_app_results = [*exe_summary.results, *static_results]
        change_summary = ChangeSummary()
        try:
            change_db = ApplicationChangeStory(self.cache_dir)
            change_summary = change_db.compare(all_app_results)
            change_db.update(all_app_results)
            change_db.save()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"application change database recovered error: {exc}")
            self.log("WARN", errors[-1])

        if baseline is not None:
            try:
                baseline.update(inventory.items)
                baseline.save()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"location baseline save recovered error: {exc}")
                self.log("WARN", errors[-1])

        metrics, coverage = self._jar_metrics(jar_results)
        groups = grouped_findings(jar_results, exe_summary.results, static_results)
        health = build_scan_health(
            inventory.stats,
            exe_summary.results,
            static_results,
            jar_partial=sum(1 for item in jar_results if item.analysis_status == "PARTIAL_ANALYSIS"),
        )
        health.recovered_errors += len(errors)

        summary = ScanSummary(
            started_at=started,
            generated_at=dt.datetime.now().replace(microsecond=0),
            locations=locations,
            jar_results=jar_results,
            executable_results=exe_summary.results,
            exe_summary=exe_summary,
            inventory_result=inventory,
            static_results=static_results,
            grouped_findings=groups,
            change_summary=change_summary,
            scan_health=health,
            official_version_jars=reference_jars,
            skipped_errors=[*errors, *inventory.stats.notes],
            new_jars=int(jar_diff["new"]),
            changed_jars=int(jar_diff["changed"]),
            removed_jars=int(jar_diff["removed"]),
            renamed_or_similar_jars=int(jar_diff["renamed_or_similar"]),
            important_changes=[*list(jar_diff["important"]), *change_summary.important],
            analysis_coverage=coverage,
            analysis_metrics=metrics,
            mousetweaks_findings=mousetweaks_findings,
            freecam_findings=freecam_findings,
            autoclicker_findings=autoclicker_findings,
        )
        self.log("REPORT", "Writing short report...")
        try:
            report_path = write_report(summary, self.reports_dir)
        except Exception as exc:  # noqa: BLE001
            summary.skipped_errors.append(f"primary report path recovered error: {exc}")
            report_path = write_report(summary, application_root() / "reports")
        try:
            write_json_summary(summary, report_path)
        except Exception as exc:  # noqa: BLE001
            summary.skipped_errors.append(f"json summary recovered error: {exc}")
        return summary


    def run_category(self, category_id: str, accumulated: ScanSummary | None = None, completed_categories: set[str] | None = None) -> ScanSummary:
        """Run one user-selected scan category and update the cumulative report."""
        category_summary = self._run_single_category(category_id)
        completed = set(completed_categories or set())
        completed.add(category_id)
        category_summary.completed_categories = sorted(completed)
        category_summary.not_completed_categories = [key for key in ALL_CATEGORY_IDS if key not in completed]
        category_summary.category_summaries[category_id] = self.category_summary_line(category_id, category_summary)
        combined = merge_summaries(accumulated, category_summary) if accumulated else category_summary
        combined.completed_categories = sorted(completed)
        combined.not_completed_categories = [key for key in ALL_CATEGORY_IDS if key not in completed]
        combined.category_summaries[category_id] = self.category_summary_line(category_id, category_summary)
        self.write_summary_report(combined)
        return combined

    def write_summary_report(self, summary: ScanSummary) -> ScanSummary:
        self.log("REPORT", "Updating short report...")
        try:
            report_path = write_report(summary, self.reports_dir)
        except Exception as exc:  # noqa: BLE001
            summary.skipped_errors.append(f"primary report path recovered error: {exc}")
            report_path = write_report(summary, application_root() / "reports")
        try:
            write_json_summary(summary, report_path)
        except Exception as exc:  # noqa: BLE001
            summary.skipped_errors.append(f"json summary recovered error: {exc}")
        return summary

    def _run_single_category(self, category_id: str) -> ScanSummary:
        started = now_local()
        errors: list[str] = []
        locations: list[LauncherLocation] = []
        reference_jars: list[Path] = []
        inventory = InventoryResult()
        jar_results: list[JarScanResult] = []
        process_results: list[dict[str, object]] = []
        mousetweaks_findings: list[dict[str, object]] = []
        freecam_findings: list[dict[str, object]] = []
        autoclicker_findings: list[dict[str, object]] = []
        deleted_mod_findings: list[dict[str, object]] = []
        exe_summary = ExeScanSummary()
        static_results: list[StaticAnalysisResult] = []
        change_summary = ChangeSummary()
        jar_diff: dict[str, object] = {"new": 0, "changed": 0, "removed": 0, "renamed_or_similar": 0, "important": []}

        if category_id in {"minecraft", "javaw_scan", "mousetweaks", "freecam", "mousetweaks_freecam", "xray_autoclicker"} and self.enable_launcher_discovery:
            self.log("DISCOVERY", "Searching launcher folders...")
            try:
                launcher_discovery = LauncherDiscovery(log=self.log)
                locations, reference_jars, discovery_errors = launcher_discovery.discover()
                errors.extend(discovery_errors)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"launcher discovery recovered error: {exc}")
                self.log("WARN", errors[-1])

        baseline = None
        try:
            baseline = LocationBaseline(self.cache_dir)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"location baseline recovered error: {exc}")
            self.log("WARN", errors[-1])

        if category_id not in {"minecraft", "manual_jar", "javaw_scan", "mousetweaks", "freecam", "mousetweaks_freecam", "xray_autoclicker"}:
            try:
                roots = self._category_inventory_roots(category_id)
                max_files = self._category_max_files(category_id)
                inventory = InventoryScanner(log=self.log, roots=roots, max_files=max_files).scan()
            except Exception as exc:  # noqa: BLE001
                inventory = InventoryResult()
                inventory.stats.errors_recovered += 1
                inventory.stats.notes.append(f"inventory phase recovered error: {exc}")
                errors.append(inventory.stats.notes[-1])
                self.log("WARN", errors[-1])

        try:
            deep_queue = build_deep_analysis_queue(inventory.items, baseline)
            # Installed Apps Review is explicitly selected by the user, so it should
            # inspect PE files in Program Files/ProgramData instead of letting the
            # generic quick-scan queue skip signed-baseline candidates. Other
            # categories keep the candidate filter for speed.
            source_items = inventory.items if category_id == "installed_apps" else deep_queue.items
            queue_items = self._filter_queue_for_category(category_id, source_items)
        except Exception as exc:  # noqa: BLE001
            queue_items = []
            errors.append(f"deep analysis queue recovered error: {exc}")
            self.log("WARN", errors[-1])
        if category_id not in {"minecraft", "manual_jar", "javaw_scan", "mousetweaks", "freecam", "mousetweaks_freecam"}:
            self.log("SCAN", f"Deep analysis queue: {len(queue_items)} files")
            self.log("WORKER", f"{default_worker_count(len(queue_items))} analysis workers active")

        if category_id == "minecraft":
            try:
                jar_targets = self._collect_launcher_jars(locations)
                jar_results = self._scan_jars(jar_targets)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"minecraft jar analysis recovered error: {exc}")
                self.log("WARN", errors[-1])
                jar_results = []

        if category_id == "manual_jar":
            self.log("SCAN", "Manual JAR Deep Scan: cache disabled, full content analysis enabled...")
            audit_started = time.monotonic()
            self.progress(0, max(1, len(self.manual_jar_paths)), "Preparing uncached deep JAR analysis")
            scanner = JarScanner(log=self.log, cache_dir=self.cache_dir, enable_cache=False)
            for index, path in enumerate(self.manual_jar_paths, 1):
                if not path.is_file():
                    errors.append(f"manual jar not found: {path}")
                    continue
                try:
                    location = LauncherLocation("Manual Selection", path.parent.name or "Selected JAR", path.parent, "manual")
                    result = scanner.scan(path, location)
                    if os.environ.get("XIEN_CONTROL_DEEP_AUDIT") == "1":
                        self.log("AUDIT", "Running independent entry-by-entry integrity pass...")
                        result = scanner.deep_audit(path, result)
                    result.modrinth_verified = False
                    result.cache_reused = False
                    jar_results.append(result)
                    self.progress(index, len(self.manual_jar_paths), f"Deep analysis complete: {path.name}")
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"manual jar analysis recovered error ({path.name}): {exc}")
                    self.log("WARN", errors[-1])
            minimum = float(os.environ.get("XIEN_CONTROL_DEEP_AUDIT_MIN_SECONDS", "0") or 0)
            remaining = max(0.0, minimum - (time.monotonic() - audit_started))
            if remaining:
                self.log("AUDIT", "Final concealment and integrity review in progress...")
                deadline = time.monotonic() + remaining
                while time.monotonic() < deadline:
                    left = max(0, int(deadline - time.monotonic()))
                    self.progress(0, 1, f"Final integrity review ({left}s remaining)")
                    time.sleep(min(1.0, max(0.01, deadline - time.monotonic())))

        if category_id == "mousetweaks":
            mousetweaks_findings = self._find_mousetweaks(locations, [], errors)
        if category_id == "freecam":
            freecam_findings = self._find_freecam(locations, [], errors)
        if category_id == "mousetweaks_freecam":
            self.log("SCAN", "MouseTweaks / Freecam Finder: checking instance logs and mod contents...")
            mousetweaks_findings = self._find_mousetweaks(locations, [], errors)
            freecam_findings = self._find_freecam(locations, [], errors)
        if category_id == "xray_autoclicker":
            autoclicker_findings = self._find_autoclicker(locations, [], errors)

        if category_id in {"minecraft", "javaw_scan"} and locations:
            self.log("TRACE", "Checking instance logs, config, and launcher metadata for removed mod traces...")
            try:
                deleted_mod_findings = DeletedModTraceFinder().scan(locations)
                self.log("TRACE", f"Removed mod trace review complete: {len(deleted_mod_findings)} trace(s)")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"deleted mod trace scan recovered error: {exc}")
                self.log("WARN", errors[-1])

        if category_id == "javaw_scan":
            self.log("SCAN", "Scanning active javaw.exe processes...")
            try:
                installed_mod_paths = [path for location in locations for path in _safe_mod_jars(location.mods_path)]
                process_results = [item.to_dict() for item in JavaProcessScannerEngine().scan(installed_mod_paths)]
                if not process_results:
                    self.log("WARN", "No active javaw.exe process found; live memory scan skipped.")
                else:
                    findings = sum(len(item.get("findings", [])) for item in process_results)
                    self.log("PROCESS", f"javaw.exe scan complete: {len(process_results)} process(es), {findings} finding(s)")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"javaw.exe process scan recovered error: {exc}")
                self.log("WARN", errors[-1])

        pe_items = [item for item in queue_items if is_pe_type(item.file_type)]
        static_items = [
            item for item in queue_items
            if is_script_type(item.file_type) or is_shortcut_type(item.file_type) or is_installer_type(item.file_type) or is_archive_type(item.file_type)
        ]
        if category_id in {"quick_windows", "installed_apps"}:
            try:
                exe_summary = self._scan_pe_items(pe_items, inventory.stats)
            except Exception as exc:  # noqa: BLE001
                exe_summary = ExeScanSummary(stats=ExeDiscoveryStats(discovery_notes=[f"PE analysis recovered error: {exc}"], errors_recovered=1))
                errors.append(exe_summary.stats.discovery_notes[-1])
                self.log("WARN", errors[-1])
        if category_id == "other_files":
            try:
                static_results = self._scan_static_items(static_items)
            except Exception as exc:  # noqa: BLE001
                static_results = []
                errors.append(f"extra file type analysis recovered error: {exc}")
                self.log("WARN", errors[-1])

        if jar_results:
            try:
                correlate_results(jar_results)
                for item in jar_results:
                    if item.correlation_notes:
                        breakdown = calculate_jar_risk(item)
                        item.risk_score = breakdown.score
                        item.verdict = breakdown.verdict
                        item.risk_reasons = breakdown.reasons
            except Exception as exc:  # noqa: BLE001
                errors.append(f"correlation recovered error: {exc}")
                self.log("WARN", errors[-1])
            try:
                artifact_db = ArtifactDatabase(self.cache_dir)
                jar_diff = artifact_db.compare_previous(jar_results)
                artifact_db.update(jar_results)
                artifact_db.save()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"jar artifact database recovered error: {exc}")
                self.log("WARN", errors[-1])

        all_app_results = [*exe_summary.results, *static_results]
        if all_app_results:
            try:
                change_db = ApplicationChangeStory(self.cache_dir)
                change_summary = change_db.compare(all_app_results)
                change_db.update(all_app_results)
                change_db.save()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"application change database recovered error: {exc}")
                self.log("WARN", errors[-1])

        if baseline is not None and inventory.items:
            try:
                baseline.update(inventory.items)
                baseline.save()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"location baseline save recovered error: {exc}")
                self.log("WARN", errors[-1])

        metrics, jar_coverage = self._jar_metrics(jar_results)
        groups = grouped_findings(jar_results, exe_summary.results, static_results)
        health = build_scan_health(
            inventory.stats,
            exe_summary.results,
            static_results,
            jar_partial=sum(1 for item in jar_results if item.analysis_status == "PARTIAL_ANALYSIS"),
        )
        health.recovered_errors += len(errors)
        coverage = self._category_coverage_label(category_id, inventory, jar_results, exe_summary, static_results, health, jar_coverage)
        summary = ScanSummary(
            started_at=started,
            generated_at=dt.datetime.now().replace(microsecond=0),
            locations=locations,
            jar_results=jar_results,
            executable_results=exe_summary.results,
            exe_summary=exe_summary,
            inventory_result=inventory,
            static_results=static_results,
            grouped_findings=groups,
            change_summary=change_summary,
            scan_health=health,
            official_version_jars=reference_jars,
            skipped_errors=[*errors, *inventory.stats.notes],
            new_jars=int(jar_diff["new"]),
            changed_jars=int(jar_diff["changed"]),
            removed_jars=int(jar_diff["removed"]),
            renamed_or_similar_jars=int(jar_diff["renamed_or_similar"]),
            important_changes=[*list(jar_diff["important"]), *change_summary.important],
            analysis_coverage=coverage,
            analysis_metrics=metrics,
            process_results=process_results,
            mousetweaks_findings=mousetweaks_findings,
            freecam_findings=freecam_findings,
            autoclicker_findings=autoclicker_findings,
            deleted_mod_findings=deleted_mod_findings,
        )
        return summary

    def _find_mousetweaks(
        self,
        locations: list[LauncherLocation],
        jar_results: list[JarScanResult],
        errors: list[str],
    ) -> list[dict[str, object]]:
        self.log("SCAN", "MouseTweaks Finder: checking instance logs and mod contents...")
        try:
            findings = MouseTweaksFinder().scan(locations, jar_results)
            self.log("MOUSE", f"MouseTweaks Finder complete: {len(findings)} trace(s)")
            return findings
        except Exception as exc:  # noqa: BLE001
            message = f"MouseTweaks Finder recovered error: {exc}"
            errors.append(message)
            self.log("WARN", message)
            return []

    def _find_freecam(self, locations, jar_results, errors):
        self.log("SCAN", "Freecam Finder: checking instance logs and mod contents...")
        try:
            findings = FreecamFinder().scan(locations, jar_results)
            self.log("FREECAM", f"Freecam Finder complete: {len(findings)} trace(s)")
            return findings
        except Exception as exc:  # noqa: BLE001
            message = f"Freecam Finder recovered error: {exc}"
            errors.append(message)
            self.log("WARN", message)
            return []

    def _find_autoclicker(self, locations, jar_results, errors):
        self.log("SCAN", "AutoClicker Finder: checking instance logs and mod contents...")
        try:
            findings = AutoClickerFinder().scan(locations, jar_results)
            self.log("CLICK", f"AutoClicker Finder complete: {len(findings)} trace(s)")
            return findings
        except Exception as exc:  # noqa: BLE001
            message = f"AutoClicker Finder recovered error: {exc}"
            errors.append(message)
            self.log("WARN", message)
            return []

    def category_summary_line(self, category_id: str, summary: ScanSummary) -> str:
        duration = int(max(0, (summary.generated_at - summary.started_at).total_seconds()))
        if category_id == "minecraft":
            return f"Scanned Jars: {summary.scanned_jars} | Review Items: {len(summary.suspicious_jars)} | Duration: {_duration(duration)}"
        if category_id == "manual_jar":
            return f"Deep-scanned JARs: {summary.scanned_jars} | Review Items: {len(summary.suspicious_jars)} | Duration: {_duration(duration)}"
        if category_id == "javaw_scan":
            findings = sum(len(item.get("findings", [])) for item in summary.process_results)
            return f"Java Processes: {len(summary.process_results)} | Findings: {findings} | Duration: {_duration(duration)}"
        if category_id == "mousetweaks":
            return f"MouseTweaks Traces: {len(summary.mousetweaks_findings)} | Duration: {_duration(duration)}"
        if category_id == "freecam":
            return f"Freecam/FreeLook Traces: {len(summary.freecam_findings)} | Duration: {_duration(duration)}"
        if category_id == "mousetweaks_freecam":
            return f"MouseTweaks: {len(summary.mousetweaks_findings)} | Freecam: {len(summary.freecam_findings)} | Duration: {_duration(duration)}"
        if category_id == "xray_autoclicker":
            return f"Xray/Clicker/Totem/Mace Traces: {len(summary.autoclicker_findings)} | Duration: {_duration(duration)}"
        if category_id in {"quick_windows", "installed_apps"}:
            return f"Analyzed Apps: {len(summary.exe_summary.results)} | Review Items: {len(summary.exe_summary.review_items)} | Duration: {_duration(duration)}"
        if category_id == "other_files":
            return f"Analyzed Files: {len(summary.static_results)} | Review Items: {sum(1 for item in summary.static_results if item.review)} | Duration: {_duration(duration)}"
        return f"Jars: {summary.scanned_jars} | Apps: {len(summary.exe_summary.results)} | Other: {len(summary.static_results)} | Duration: {_duration(duration)}"

    def _category_inventory_roots(self, category_id: str) -> list[Path] | None:
        if self.inventory_roots is not None:
            return self.inventory_roots
        if category_id == "quick_windows":
            return quick_windows_roots()
        if category_id == "installed_apps":
            return installed_app_roots()
        if category_id == "other_files":
            return other_file_roots()
        return []

    def _category_max_files(self, category_id: str) -> int | None:
        if self.max_inventory_files is not None:
            return self.max_inventory_files
        return {
            "quick_windows": 18_000,
            "installed_apps": 28_000,
            "other_files": 18_000,
        }.get(category_id)

    def _filter_queue_for_category(self, category_id: str, items: list[FileInventoryItem]) -> list[FileInventoryItem]:
        if category_id == "quick_windows":
            return [item for item in items if is_pe_type(item.file_type)]
        if category_id == "installed_apps":
            return [item for item in items if is_pe_type(item.file_type) and item.folder_category in {"PROGRAM_FILES", "PROGRAMDATA", "UNKNOWN_USER_FOLDER"}]
        if category_id == "other_files":
            return [item for item in items if is_script_type(item.file_type) or is_shortcut_type(item.file_type) or is_installer_type(item.file_type) or is_archive_type(item.file_type)]
        return []

    def _category_coverage_label(self, category_id: str, inventory: InventoryResult, jar_results: list[JarScanResult], exe_summary: ExeScanSummary, static_results: list[StaticAnalysisResult], health, jar_coverage: str) -> str:
        if category_id == "minecraft":
            return jar_coverage
        if category_id == "manual_jar":
            return jar_coverage
        if category_id == "javaw_scan":
            return "High"
        if category_id == "mousetweaks":
            return "High"
        if category_id in {"freecam", "mousetweaks_freecam"}:
            return "High"
        candidates = len(exe_summary.results) + len(static_results) + len(jar_results)
        issues = health.partial_analysis_items + health.unreadable_files + health.invalid_archives + health.invalid_pe_files
        if candidates == 0 and inventory.stats.supported_files == 0:
            return "High"
        ratio = 1.0 - min(1.0, issues / max(1, candidates + inventory.stats.supported_files))
        return "High" if ratio >= 0.9 else ("Medium" if ratio >= 0.65 else "Partial")

    def _scan_jars(self, jar_targets: list[tuple[Path, LauncherLocation]]) -> list[JarScanResult]:
        # JAR analysis is independent per file.  Use a read-only scanner shared by
        # workers and keep cache writes on the coordinator thread, avoiding cache
        # corruption while allowing decompression/bytecode work to overlap.
        cache_scanner = JarScanner(log=self.log, cache_dir=self.cache_dir)
        scanner = JarScanner(log=self.log, cache_dir=self.cache_dir, enable_cache=False)
        modrinth = ModrinthVerifier()
        total = len(jar_targets)
        if not jar_targets:
            self.log("WARN", "No Minecraft jar files found in inventory or launcher folders.")

        deep_enabled = os.environ.get("XIEN_CONTROL_DEEP_AUDIT_MODS", "0") == "1"
        cache_lock = threading.Lock()
        modrinth_lock = threading.Lock()
        self.log("MODRINTH", f"Hash verification {'enabled' if modrinth.enabled else 'disabled'} for this scan")
        results: list[JarScanResult | None] = [None] * total
        tasks = []
        matches: dict[int, ModrinthMatch] = {}
        # Prepare hashes/cache on the coordinator, then send only uncached work
        # to separate processes. This keeps cache writes and Modrinth state safe.
        for index, (jar_path, location) in enumerate(jar_targets):
            try:
                digest, modrinth_digest = sha256_sha512_file(jar_path)
                stat = jar_path.stat()
                last_modified = dt.datetime.fromtimestamp(stat.st_mtime).replace(microsecond=0)
                cached = cache_scanner.cache.get(jar_path, digest, stat.st_size, last_modified) if cache_scanner.cache else None
                if cached is not None and not modrinth.enabled:
                    cached.modrinth_verified = False
                    cached.modrinth_project_id = ""
                    cached.modrinth_version_id = ""
                    cached.modrinth_version_name = ""
                    cached.modrinth_version_number = ""
                    cached.modrinth_project_url = ""
                match = None
                if cached is not None and modrinth.enabled and cached.modrinth_verified:
                    self.log("CACHE", f"reused Modrinth identity for {jar_path.name}")
                else:
                    with modrinth_lock:
                        match = modrinth.lookup(modrinth_digest)
                if cached is not None and (not deep_enabled or cached.deep_audit_entries):
                    cached.launcher_name = location.launcher_name
                    cached.instance_name = location.instance_name
                    cached.instance_context = cache_scanner._instance_context(location, cached)
                    results[index] = cached
                    self.log("CACHE", f"reused analysis for {jar_path.name}")
                else:
                    tasks.append((index, str(jar_path), location, digest, str(self.cache_dir), deep_enabled))
                if match is not None:
                    matches[index] = match
                elif cached is not None and modrinth.enabled and cached.modrinth_verified:
                    matches[index] = ModrinthMatch(
                        cached.modrinth_project_id,
                        cached.modrinth_version_id,
                        cached.modrinth_version_name,
                        cached.modrinth_version_number,
                        cached.modrinth_project_url,
                    )
            except Exception as exc:  # noqa: BLE001
                results[index] = _failed_jar_result(jar_path, location, exc)

        workers = min(5, total) if total else 1
        self.log("WORKER", f"Minecraft multiprocessing workers active: {workers}; queued jobs: {len(tasks)}")
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_scan_jar_process_worker, task) for task in tasks]
            done = 0
            for future in as_completed(futures):
                index, result, messages = future.result()
                for tag, message in messages:
                    self.log(tag, message)
                results[index] = result
                done += 1
                self.progress(done, total, result.file_name)

        finalized = [item for item in results if item is not None]
        for index, match in matches.items():
            result = results[index]
            if result is None:
                continue
            _apply_modrinth_match(result, match)
            breakdown = calculate_jar_risk(result)
            result.risk_score = breakdown.score
            result.verdict = breakdown.verdict
            result.risk_reasons = breakdown.reasons
            self.log("OK", f"Modrinth verified; local analysis retained: {result.file_name}")
        for result in finalized:
            if result.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}:
                self.log("ALERT", f"Suspicious: {result.file_name} | {result.verdict} {result.risk_score}/100")
        if cache_scanner.cache:
            for result in finalized:
                if not result.error:
                    cache_scanner.cache.put(result)
            cache_scanner.cache.save()
        if modrinth.enabled:
            verified_count = sum(1 for result in finalized if result.modrinth_verified)
            self.log("MODRINTH", f"Exact published hashes verified: {verified_count}/{total}")
        if total:
            self.progress(total, total, "jar scan complete")
        return finalized

    def _scan_pe_items(self, pe_items: list[FileInventoryItem], inventory_stats) -> object:
        scanner = WindowsExeScanner(cache_dir=self.cache_dir, log=self.log, enable_cache=True)
        db = ExeArtifactDatabase(self.cache_dir)

        def worker(item: FileInventoryItem):
            return scanner.analyze_file(item.path, newly_seen=not db.has_seen_path(item.path), file_type=item.file_type)

        self.log("SCAN", f"PE deep analysis queue: {len(pe_items)} files")
        results = run_parallel(pe_items, worker, progress=self.progress, error_handler=_failed_pe_result)
        stats = ExeDiscoveryStats(
            scanned_folders=inventory_stats.scanned_folders,
            skipped_folders=inventory_stats.skipped_folders,
            exe_found=sum(1 for item in pe_items if item.file_type == "PE_EXE"),
            duplicate_realpaths=inventory_stats.duplicate_realpaths,
            errors_recovered=inventory_stats.errors_recovered,
            discovery_notes=list(inventory_stats.notes),
        )
        try:
            summary = scanner.finalize_results(results, stats=stats)
        except Exception as exc:  # noqa: BLE001
            self.log("WARN", f"PE cache/artifact update recovered error: {exc}")
            summary = ExeScanSummary(results=results, stats=stats)
        summary.elapsed_seconds = 0.0
        return summary

    def _scan_static_items(self, items: list[FileInventoryItem]) -> list[StaticAnalysisResult]:
        analyzers = {
            "script": ScriptAnalyzer(),
            "shortcut": ShortcutAnalyzer(),
            "installer": InstallerAnalyzer(),
            "archive": ArchiveScanner(),
        }

        def worker(item: FileInventoryItem) -> StaticAnalysisResult:
            if is_script_type(item.file_type):
                return analyzers["script"].analyze(item)
            if is_shortcut_type(item.file_type):
                return analyzers["shortcut"].analyze(item)
            if is_installer_type(item.file_type):
                return analyzers["installer"].analyze(item)
            return analyzers["archive"].analyze(item)

        self.log("SCAN", f"Static file deep analysis queue: {len(items)} files")
        return run_parallel(items, worker, progress=self.progress, error_handler=_failed_static_result)

    def _collect_launcher_jars(self, locations: list[LauncherLocation]) -> list[tuple[Path, LauncherLocation]]:
        targets: list[tuple[Path, LauncherLocation]] = []
        seen: set[str] = set()
        for location in locations:
            try:
                paths = [path for path in location.mods_path.rglob("*") if path.is_file() and is_java_archive_candidate(path, broad=True)]
            except (OSError, PermissionError) as exc:
                self.log("WARN", f"Cannot read mods folder: {location.mods_path} ({exc})")
                continue
            for jar in sorted(paths, key=lambda value: value.name.lower()):
                ok, archive_type = identify_java_archive(jar, broad=True)
                if not ok:
                    continue
                key = _key(jar)
                if key in seen:
                    continue
                if archive_type == "java_archive_nonstandard_extension":
                    self.log("FOUND", f"Java archive with non-standard extension: {jar}")
                seen.add(key)
                targets.append((jar, location))
        return targets

    def _jar_targets_from_inventory(self, items: list[FileInventoryItem]) -> list[tuple[Path, LauncherLocation]]:
        targets = []
        for item in items:
            if item.file_type != "JAVA_ARCHIVE":
                continue
            location = LauncherLocation(
                launcher_name="Fast Inventory",
                instance_name=item.folder_category,
                mods_path=item.path.parent,
                source="fast inventory",
                location_type="jar_file",
            )
            targets.append((item.path, location))
        return targets

    def _merge_jar_targets(self, primary: list[tuple[Path, LauncherLocation]], extra: list[tuple[Path, LauncherLocation]]) -> list[tuple[Path, LauncherLocation]]:
        out = []
        seen = set()
        for path, location in [*primary, *extra]:
            key = _key(path)
            if key in seen:
                continue
            seen.add(key)
            out.append((path, location))
        return out

    def _jar_metrics(self, results: list[JarScanResult]) -> tuple[dict[str, int], str]:
        analyzed_jars = len(results)
        partial = sum(1 for item in results if item.analysis_status == "PARTIAL_ANALYSIS")
        failed = sum(1 for item in results if item.analysis_status == "FAILED_ANALYSIS")
        metrics = {
            "analyzed_jars": analyzed_jars,
            "analyzed_classes": sum(item.classes_analyzed_count for item in results),
            "parsed_attributes": sum(item.parsed_attributes_count for item in results),
            "analyzed_resources": sum(item.resources_analyzed_count for item in results),
            "partial_analysis_count": partial,
            "cache_hits": sum(1 for item in results if item.cache_reused),
            "errors_recovered": sum(1 for item in results if item.error or item.zip_anomalies),
        }
        if analyzed_jars == 0:
            return metrics, "Unknown"
        ratio = 1 - ((partial + failed * 2) / max(1, analyzed_jars * 2))
        return metrics, "High" if ratio >= 0.9 else ("Medium" if ratio >= 0.65 else "Low")



def merge_summaries(base: ScanSummary, new: ScanSummary) -> ScanSummary:
    """Merge one category summary into the cumulative scan summary."""
    base.generated_at = new.generated_at
    base.locations = _dedupe_by_key([*base.locations, *new.locations], lambda item: f"{item.launcher_name}|{item.instance_name}|{item.mods_path}".lower())
    base.jar_results = _dedupe_by_path([*base.jar_results, *new.jar_results])
    exe_results = _dedupe_by_path([*base.exe_summary.results, *new.exe_summary.results])
    base.exe_summary.results = exe_results
    base.executable_results = exe_results
    base.static_results = _dedupe_by_path([*base.static_results, *new.static_results])
    base.official_version_jars = _dedupe_paths([*base.official_version_jars, *new.official_version_jars])
    base.inventory_result = _merge_inventory(base.inventory_result, new.inventory_result)
    base.grouped_findings = grouped_findings(base.jar_results, base.exe_summary.results, base.static_results)
    base.change_summary = _merge_change_summary(base.change_summary, new.change_summary)
    base.scan_health = _merge_health(base.scan_health, new.scan_health)
    base.skipped_errors = [*base.skipped_errors, *new.skipped_errors]
    base.new_jars += new.new_jars
    base.changed_jars += new.changed_jars
    base.removed_jars += new.removed_jars
    base.renamed_or_similar_jars += new.renamed_or_similar_jars
    base.important_changes = [*base.important_changes, *new.important_changes]
    base.analysis_metrics = _merge_metrics(base.analysis_metrics, new.analysis_metrics)
    base.process_results = _dedupe_by_key([*base.process_results, *new.process_results], lambda item: str(item.get("pid", "")))
    base.mousetweaks_findings = _dedupe_by_key(
        [*base.mousetweaks_findings, *new.mousetweaks_findings],
        lambda item: f"{item.get('source_type')}|{item.get('path')}|{item.get('evidence')}",
    )
    base.freecam_findings = _dedupe_by_key(
        [*base.freecam_findings, *new.freecam_findings],
        lambda item: f"{item.get('source_type')}|{item.get('path')}|{item.get('evidence')}",
    )
    base.autoclicker_findings = _dedupe_by_key(
        [*base.autoclicker_findings, *new.autoclicker_findings],
        lambda item: f"{item.get('source_type')}|{item.get('path')}|{item.get('evidence')}",
    )
    base.deleted_mod_findings = _dedupe_by_key(
        [*base.deleted_mod_findings, *new.deleted_mod_findings],
        lambda item: f"{item.get('source_type')}|{item.get('path')}|{item.get('mod_name')}",
    )
    base.analysis_coverage = _coverage_from_health(base.scan_health)
    base.exe_summary.cache_hits += new.exe_summary.cache_hits
    base.exe_summary.cache_misses += new.exe_summary.cache_misses
    base.exe_summary.duplicate_hashes += new.exe_summary.duplicate_hashes
    base.exe_summary.new_since_last_scan += new.exe_summary.new_since_last_scan
    base.exe_summary.changed_since_last_scan += new.exe_summary.changed_since_last_scan
    base.exe_summary.same_hash_different_path += new.exe_summary.same_hash_different_path
    base.exe_summary.important_changes = [*base.exe_summary.important_changes, *new.exe_summary.important_changes]
    return base


def quick_windows_roots() -> list[Path]:
    home = Path.home()
    return _existing_roots([
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        home / "AppData" / "Roaming",
        home / "AppData" / "Local",
        Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path.home() / "AppData" / "Local" / "Temp",
    ])


def _safe_mod_jars(mods_path: Path) -> list[Path]:
    try:
        root = Path(mods_path)
        if not root.is_dir():
            return []
        return [
            path
            for path in root.iterdir()
            if path.is_file() and path.name.lower().endswith((".jar", ".jar.disabled", ".jar.bak", ".jar.old"))
        ]
    except OSError:
        return []


def installed_app_roots() -> list[Path]:
    import os
    return _existing_roots([
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("ProgramData", r"C:\ProgramData")),
    ])


def other_file_roots() -> list[Path]:
    # Other static file review focuses on user-controlled and high-value locations.
    return _existing_roots([*quick_windows_roots(), *installed_app_roots()])


def _existing_roots(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        key = str(resolved).lower()
        if key in seen or not resolved.exists() or not resolved.is_dir():
            continue
        seen.add(key)
        out.append(resolved)
    return out


def _duration(seconds: int) -> str:
    minutes, sec = divmod(max(0, seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{sec:02d}"
    return f"{minutes:02d}:{sec:02d}"


def _dedupe_by_path(items):
    out = []
    seen = set()
    for item in items:
        path = getattr(item, "path", None)
        key = str(path).lower() if path is not None else repr(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _dedupe_by_key(items, key_fn):
    out = []
    seen = set()
    for item in items:
        key = key_fn(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _merge_inventory(a: InventoryResult, b: InventoryResult) -> InventoryResult:
    result = InventoryResult(items=_dedupe_by_path([*a.items, *b.items]))
    result.stats.scanned_folders = a.stats.scanned_folders + b.stats.scanned_folders
    result.stats.skipped_folders = a.stats.skipped_folders + b.stats.skipped_folders
    result.stats.permission_denied = a.stats.permission_denied + b.stats.permission_denied
    result.stats.files_seen = a.stats.files_seen + b.stats.files_seen
    result.stats.supported_files = len(result.items)
    result.stats.duplicate_realpaths = a.stats.duplicate_realpaths + b.stats.duplicate_realpaths
    result.stats.errors_recovered = a.stats.errors_recovered + b.stats.errors_recovered
    result.stats.notes = [*a.stats.notes, *b.stats.notes]
    return result


def _merge_change_summary(a: ChangeSummary, b: ChangeSummary) -> ChangeSummary:
    return ChangeSummary(
        new_application_files=a.new_application_files + b.new_application_files,
        changed_known_files=a.changed_known_files + b.changed_known_files,
        new_review_items=a.new_review_items + b.new_review_items,
        same_hash_different_names=a.same_hash_different_names + b.same_hash_different_names,
        recent_review_items_24h=a.recent_review_items_24h + b.recent_review_items_24h,
        recent_review_items_72h=a.recent_review_items_72h + b.recent_review_items_72h,
        important=[*a.important, *b.important],
    )


def _merge_health(a, b):
    from .static_models import ScanHealth
    return ScanHealth(
        skipped_folders=a.skipped_folders + b.skipped_folders,
        permission_denied=a.permission_denied + b.permission_denied,
        unreadable_files=a.unreadable_files + b.unreadable_files,
        invalid_archives=a.invalid_archives + b.invalid_archives,
        invalid_pe_files=a.invalid_pe_files + b.invalid_pe_files,
        partial_analysis_items=a.partial_analysis_items + b.partial_analysis_items,
        signature_check_unknown=a.signature_check_unknown + b.signature_check_unknown,
        cache_errors_recovered=a.cache_errors_recovered + b.cache_errors_recovered,
        recovered_errors=a.recovered_errors + b.recovered_errors,
    )


def _merge_metrics(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    out = dict(a)
    for key, value in b.items():
        out[key] = out.get(key, 0) + int(value)
    return out


def _coverage_from_health(health) -> str:
    issues = health.partial_analysis_items + health.unreadable_files + health.invalid_archives + health.invalid_pe_files + health.permission_denied
    if issues == 0:
        return "High"
    if issues <= 10:
        return "Medium"
    return "Partial"

def application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def downloads_dir() -> Path:
    downloads = Path.home() / "Downloads"
    return downloads if downloads.exists() else application_root() / "reports"


def report_storage_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "VeyraScan" / "reports"


def _key(path: Path) -> str:
    try:
        return str(path.resolve()).lower()
    except OSError:
        return str(path).lower()


def _modrinth_verified_result(path: Path, location: LauncherLocation, digest: str, match: ModrinthMatch) -> JarScanResult:
    stat = path.stat()
    return JarScanResult(
        path=path,
        file_name=path.name,
        sha256=digest,
        size_bytes=stat.st_size,
        last_modified=dt.datetime.fromtimestamp(stat.st_mtime).replace(microsecond=0),
        launcher_name=location.launcher_name,
        instance_name=location.instance_name,
        risk_score=0,
        verdict="CLEAN",
        analysis_confidence_score=100,
        analysis_confidence="High",
        analysis_status="SKIPPED_MODRINTH_VERIFIED",
        known_hash_status="MODRINTH_VERIFIED",
        risk_reasons=["SHA-256 hash exactly matches a file published on Modrinth."],
        modrinth_verified=True,
        modrinth_project_id=match.project_id,
        modrinth_version_id=match.version_id,
        modrinth_version_name=match.version_name,
        modrinth_version_number=match.version_number,
        modrinth_project_url=match.project_url,
    )


def _apply_modrinth_match(result: JarScanResult, match: ModrinthMatch) -> JarScanResult:
    """Attach registry identity to a fully scanned result without changing its verdict."""
    result.modrinth_verified = True
    result.modrinth_project_id = match.project_id
    result.modrinth_version_id = match.version_id
    result.modrinth_version_name = match.version_name
    result.modrinth_version_number = match.version_number
    result.modrinth_project_url = match.project_url
    return result


def _failed_jar_result(path: Path, location: LauncherLocation, exc: Exception) -> JarScanResult:
    try:
        stat = path.stat()
        size = stat.st_size
        modified = dt.datetime.fromtimestamp(stat.st_mtime).replace(microsecond=0)
    except OSError:
        size = 0
        modified = dt.datetime.fromtimestamp(0)
    return JarScanResult(
        path=path,
        file_name=path.name,
        sha256="",
        size_bytes=size,
        last_modified=modified,
        launcher_name=location.launcher_name,
        instance_name=location.instance_name,
        risk_score=0,
        verdict="CLEAN",
        analysis_confidence="Low",
        analysis_status="FAILED_ANALYSIS",
        error=f"jar analysis recovered error: {exc}",
    )


def _failed_pe_result(item: FileInventoryItem, exc: Exception) -> ExeScanResult:
    return ExeScanResult(
        path=item.path,
        file_name=item.file_name,
        size_bytes=item.size_bytes,
        created_time=item.created_time,
        last_modified=item.last_modified,
        file_type=item.file_type,
        folder_category=item.folder_category,
        confidence="LOW",
        analysis_mode="FAILED",
        risk_score=45,
        verdict="REVIEW",
        reasons=[f"PE analysis recovered error: {exc}"],
        evidence=["analysis worker recovered error"],
        error=str(exc),
    )


def _failed_static_result(item: FileInventoryItem, exc: Exception) -> StaticAnalysisResult:
    return StaticAnalysisResult(
        path=item.path,
        file_name=item.file_name,
        file_type=item.file_type,
        size_bytes=item.size_bytes,
        last_modified=item.last_modified,
        folder_category=item.folder_category,
        verdict="REVIEW",
        priority="NORMAL",
        confidence="LOW",
        risk_score=45,
        reasons=[f"static analysis recovered error: {exc}"],
        evidence=["analysis worker recovered error"],
        error=str(exc),
    )
