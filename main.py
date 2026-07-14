from __future__ import annotations

import multiprocessing

from xien_control.banner import BANNER, SUBTITLE
from xien_control.console import Console, ask_yes_no, pause_if_interactive
from xien_control.interactive_menu import CATEGORY_TITLES, InteractiveMenu
from xien_control.scan_orchestrator import ScanOrchestrator


def launch() -> int:
    multiprocessing.freeze_support()
    import os
    import sys

    if "--console" in sys.argv or os.environ.get("XIEN_CONTROL_CONSOLE", "").strip() == "1":
        return main()
    try:
        from xien_control.gui import launch_gui

        return launch_gui()
    except (ImportError, RuntimeError):
        return main()


def main() -> int:
    console = Console()
    console.line(BANNER)
    console.line(SUBTITLE)
    console.line()
    console.tag("BOOT", "Starting Veyra Scan")
    console.tag("LOAD", "Loading jar/exe/static analysis engine")
    console.tag("LOAD", "Loading detection rules")
    console.tag("OK", "Console initialized")
    console.tag("OK", "Safe scan policy loaded")
    console.line()

    if not ask_yes_no("Start scanning? [Y/N]: "):
        console.line("Scan cancelled.")
        pause_if_interactive()
        return 0

    orchestrator = ScanOrchestrator(log=console.tag, progress=console.progress)
    menu = InteractiveMenu(console)
    completed: set[str] = set()
    summary = None

    try:
        while True:
            category = menu.choose_category(completed)
            if category is None:
                break
            console.line()
            console.line("=" * 60)
            console.line(f"STARTING: {category.title}")
            console.line("=" * 60)
            summary = orchestrator.run_category(category.id, accumulated=summary, completed_categories=completed)
            completed.add(category.id)
            _print_category_complete(console, category.id, summary)
            if not menu.ask_more(completed):
                break
    except KeyboardInterrupt:
        console.line()
        console.line("Scan stopped by the user.")
        if summary is not None:
            try:
                orchestrator.write_summary_report(summary)
                console.line(f"Partial report saved to: {summary.report_path}")
            except Exception as exc:  # noqa: BLE001
                console.line(f"Could not write partial report: {exc}")
        pause_if_interactive()
        return 130

    if summary is None:
        console.line("No scan category was selected.")
        pause_if_interactive()
        return 0

    orchestrator.write_summary_report(summary)
    _print_final_summary(console, summary)
    console.tag("DONE", "Scan completed")
    pause_if_interactive()
    return 0


def _print_category_complete(console: Console, category_id: str, summary) -> None:
    console.line()
    console.line("-" * 60)
    console.line(f"{CATEGORY_TITLES.get(category_id, category_id)} completed.")
    if category_id == "minecraft":
        console.line(f"Scanned Jars: {summary.scanned_jars}")
        console.line(f"Review Items: {len(summary.suspicious_jars)}")
    elif category_id in {"quick_windows", "installed_apps"}:
        console.line(f"Analyzed Apps: {len(summary.exe_summary.results)}")
        console.line(f"Review Items: {len(summary.exe_summary.review_items)}")
    elif category_id == "other_files":
        static_review = sum(1 for item in summary.static_results if item.review)
        console.line(f"Analyzed Files: {len(summary.static_results)}")
        console.line(f"Review Items: {static_review}")
    else:
        review_total = len(summary.suspicious_jars) + len(summary.exe_summary.review_items) + sum(1 for item in summary.static_results if item.review)
        console.line(f"Review Items: {review_total}")
    console.line("Analysis Health:")
    console.line(f"Coverage: {summary.analysis_coverage}")
    console.line(f"Cache Hits: {summary.exe_summary.cache_hits + summary.analysis_metrics.get('cache_hits', 0)}")
    console.line(f"Skipped Folders: {summary.scan_health.skipped_folders}")
    console.line(f"Partial Items: {summary.scan_health.partial_analysis_items}")
    if summary.report_path:
        console.line(f"Report updated: {summary.report_path}")
    console.line("-" * 60)


def _print_final_summary(console: Console, summary) -> None:
    review_total = len(summary.suspicious_jars) + len(summary.exe_summary.review_items) + sum(1 for item in summary.static_results if item.review)
    high_priority = len([item for item in summary.exe_summary.review_items if item.verdict in {"HIGH_REVIEW", "CRITICAL_REVIEW"}])
    high_priority += len([item for item in summary.static_results if item.verdict in {"HIGH_REVIEW", "CRITICAL_REVIEW"}])
    high_priority += len([item for item in summary.suspicious_jars if item.verdict in {"HIGH_RISK", "CRITICAL"}])
    console.line()
    console.line("=" * 60)
    console.line("VEYRA SCAN SUMMARY")
    console.line("=" * 60)
    console.line(f"Overall        : {_overall_status(summary)}")
    console.line("Completed      : " + (", ".join(CATEGORY_TITLES.get(item, item) for item in summary.completed_categories) or "None"))
    if summary.not_completed_categories:
        console.line("Not completed  : " + ", ".join(CATEGORY_TITLES.get(item, item) for item in summary.not_completed_categories))
    console.line(f"Coverage       : {summary.analysis_coverage}")
    console.line(f"Files Seen     : {summary.inventory_result.stats.files_seen}")
    console.line(f"Review Items   : {review_total}")
    console.line(f"High Priority  : {high_priority}")
    console.line(f"Minecraft Jars : {summary.scanned_jars} scanned / {len(summary.suspicious_jars)} review")
    console.line(f"Applications   : {len(summary.exe_summary.results)} analyzed / {len(summary.exe_summary.review_items)} review")
    console.line(f"Other Items    : {len(summary.static_results)} analyzed / {sum(1 for item in summary.static_results if item.review)} review")
    if summary.report_path:
        console.line(f"Report         : {summary.report_path}")
    if summary.json_report_path:
        console.line(f"Details        : {summary.json_report_path}")
    console.line("=" * 60)


def _overall_status(summary) -> str:
    jar_verdicts = {item.verdict for item in summary.jar_results}
    pe_verdicts = {item.verdict for item in summary.exe_summary.results}
    static_verdicts = {item.verdict for item in summary.static_results}
    if jar_verdicts.intersection({"CRITICAL", "HIGH_RISK"}) or pe_verdicts.intersection({"HIGH_REVIEW", "CRITICAL_REVIEW"}) or static_verdicts.intersection({"HIGH_REVIEW", "CRITICAL_REVIEW"}):
        return "HIGH_REVIEW"
    if jar_verdicts.intersection({"SUSPICIOUS", "LOW_SIGNAL"}) or pe_verdicts.intersection({"REVIEW", "LOW_SIGNAL"}) or static_verdicts.intersection({"REVIEW", "LOW_SIGNAL"}):
        return "REVIEW_NEEDED"
    return "CLEAN"


if __name__ == "__main__":
    try:
        raise SystemExit(launch())
    except Exception as exc:  # noqa: BLE001
        print(f"\nUnexpected error: {exc}")
        raise SystemExit(1)
