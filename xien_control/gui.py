from __future__ import annotations

import os
import queue
import sys
import threading
try:
    import psutil
except ImportError:  # pragma: no cover - optional UI enhancement
    psutil = None
from html import escape
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QDialog,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .interactive_menu import CATEGORY_BY_ID
from .scan_orchestrator import ScanOrchestrator
from .process_scanner import JavaProcessScannerEngine
from .explain import report_reason


class XienControlGUI(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Veyra Scan")
        self.setFixedSize(900, 540)
        self.events: queue.Queue[tuple] = queue.Queue()
        self.running = False
        self.last_report: Path | None = None
        self.last_summary = None

        background = QLabel(self)
        background.setGeometry(0, 0, 900, 540)
        background.setPixmap(QPixmap(str(_asset_path())).scaled(900, 540, Qt.IgnoreAspectRatio, Qt.SmoothTransformation))

        panel = QFrame(self)
        panel.setObjectName("panel")
        panel.setGeometry(245, 24, 410, 492)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(30, 20, 30, 18)
        layout.setSpacing(6)

        title = QLabel("")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        subtitle = QLabel("")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        title.hide()
        subtitle.hide()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        github_link = QLabel("Discord: x1eqn<br>github.com/x1eqn")
        github_link.setAlignment(Qt.AlignCenter)
        github_link.setObjectName("githubLink")
        layout.addWidget(github_link)
        layout.addSpacing(5)

        self.options: dict[str, QPushButton] = {}
        entries = [
            ("minecraft", "Minecraft Mods"),
            ("manual_jar", "Manual JAR Deep Scan"),
            ("javaw_scan", "Javaw Scan"),
            ("mousetweaks_freecam", "MouseTweaks / Freecam Finder"),
            ("xray_autoclicker", "Xray / AutoClicker / Auto-Totem / Mace-Swap"),
        ]
        for key, text in entries:
            option = QPushButton(text)
            option.setObjectName("scanOption")
            option.setCheckable(True)
            option.setCursor(Qt.PointingHandCursor)
            # Start with no scan selected so the user explicitly chooses the
            # scope instead of accidentally launching a Minecraft scan.
            option.setChecked(False)
            option.setMinimumHeight(36)
            self.options[key] = option
            layout.addWidget(option)
            option.toggled.connect(lambda checked, selected_key=key: self._option_toggled(selected_key, checked))

        layout.addSpacing(2)
        layout.addSpacing(4)

        self.start_button = QPushButton("Start Scan")
        self.start_button.setCursor(Qt.PointingHandCursor)
        self.start_button.clicked.connect(self._start_scan)
        layout.addWidget(self.start_button)

        self.report_button = QPushButton("Show Report")
        self.report_button.setObjectName("reportButton")
        self.report_button.setCursor(Qt.PointingHandCursor)
        self.report_button.clicked.connect(self._show_report)
        self.report_button.hide()
        layout.addWidget(self.report_button)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)
        self.status = QLabel("Ready")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.resource_status = QLabel("System use: --")
        self.resource_status.setObjectName("resourceStatus")
        layout.addWidget(self.resource_status)

        privacy = QLabel("Files are never uploaded or executed", self)
        privacy.setObjectName("privacy")
        privacy.adjustSize()
        privacy.move(650, 520)

        self.setStyleSheet(_stylesheet())
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_events)
        self.timer.start(100)

    def _start_scan(self) -> None:
        if self.running:
            return
        selected = [key for key, option in self.options.items() if option.isChecked()]
        if not selected:
            QMessageBox.warning(self, "Veyra Scan", "Select at least one scan option.")
            return
        if "manual_jar" in selected:
            selected = ["manual_jar"]
            os.environ["XIEN_CONTROL_DEEP_AUDIT"] = "1"
            os.environ["XIEN_CONTROL_DEEP_AUDIT_MIN_SECONDS"] = "60"
            os.environ["XIEN_CONTROL_MODRINTH_VERIFY"] = "0"
        if "javaw_scan" in selected and not JavaProcessScannerEngine.is_administrator():
            QMessageBox.warning(
                self,
                "Administrator Access Recommended",
                "Veyra Scan is not running as administrator. The javaw.exe memory and open-handle scan will continue, but protected regions may be skipped.",
            )
        if "minecraft" in selected:
            answer = QMessageBox.question(
                self,
                "Modrinth Verification",
                "Use Modrinth hash verification for this scan?\n\nMatches identify the published file; Veyra still performs the full local analysis.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            os.environ["XIEN_CONTROL_MODRINTH_VERIFY"] = "1" if answer == QMessageBox.Yes else "0"
        else:
            os.environ["XIEN_CONTROL_MODRINTH_VERIFY"] = "0"
        os.environ["XIEN_CONTROL_SCAN_TEXTUREPACKS"] = "1"
        # Normal mod scans use the fast pass; manual JAR Deep Scan remains full.
        os.environ["XIEN_CONTROL_DEEP_AUDIT_MODS"] = "0"
        manual_jar_paths: list[Path] = []
        if "manual_jar" in selected:
            selected_path, _filter = QFileDialog.getOpenFileName(self, "Select JAR for Deep Scan", str(Path.home()), "Java Archives (*.jar);;All Files (*)")
            if not selected_path:
                return
            manual_jar_paths.append(Path(selected_path))
        self.running = True
        self.last_report = None
        self.last_summary = None
        self.report_button.hide()
        self._set_controls_enabled(False)
        self.progress.setValue(1)
        self.status.setText("Preparing scan")
        self.start_button.setText("Scanning...")
        threading.Thread(target=self._scan_worker, args=(selected, manual_jar_paths), daemon=True).start()

    def _option_toggled(self, key: str, checked: bool) -> None:
        if not checked:
            return
        if key == "manual_jar":
            for other_key, option in self.options.items():
                if other_key != key:
                    option.setChecked(False)
        elif self.options.get("manual_jar") is not None:
            self.options["manual_jar"].setChecked(False)

    def _scan_worker(self, categories: list[str], manual_jar_paths: list[Path]) -> None:
        def log(_tag: str, message: str) -> None:
            self.events.put(("status", message))

        def progress(current: int, total: int, scanning: str) -> None:
            self.events.put(("progress", int(current / max(1, total) * 100), scanning))

        try:
            scanner = ScanOrchestrator(log=log, progress=progress, manual_jar_paths=manual_jar_paths)
            summary = None
            completed: set[str] = set()
            for number, category in enumerate(categories, 1):
                self.events.put(("status", f"{CATEGORY_BY_ID[category].title} ({number}/{len(categories)})"))
                summary = scanner.run_category(category, accumulated=summary, completed_categories=completed)
                completed.add(category)
            if summary is not None:
                scanner.write_summary_report(summary)
                self.events.put(("done", str(summary.report_path or ""), summary))
        except Exception as exc:  # noqa: BLE001
            self.events.put(("error", str(exc)))

    def _poll_events(self) -> None:
        if self.running and psutil is not None:
            try:
                memory = psutil.virtual_memory().percent
                cpu = psutil.cpu_percent(interval=None)
                self.resource_status.setText(f"System use: CPU {cpu:.0f}%  |  RAM {memory:.0f}%")
            except Exception:
                pass
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "status":
                    self.status.setText(event[1])
                elif event[0] == "progress":
                    self.progress.setValue(event[1])
                    self.status.setText(event[2])
                elif event[0] == "done":
                    self.running = False
                    self.progress.setValue(100)
                    self.status.setText("Scan completed")
                    self.last_report = Path(event[1]) if event[1] else None
                    self.last_summary = event[2]
                    self.report_button.setVisible(self.last_report is not None)
                    self._set_controls_enabled(True)
                    self.start_button.setText("Start Scan")
                    self.resource_status.setText("System use: scan finished")
                    QMessageBox.information(self, "Veyra Scan", "Scan completed. You can read the report inside the application.")
                elif event[0] == "error":
                    self.running = False
                    self.status.setText("Scan failed")
                    self._set_controls_enabled(True)
                    self.start_button.setText("Start Scan")
                    QMessageBox.critical(self, "Veyra Scan", event[1])
        except queue.Empty:
            pass

    def _set_controls_enabled(self, enabled: bool) -> None:
        for option in self.options.values():
            option.setEnabled(enabled)
        self.start_button.setEnabled(enabled)

    def _show_report(self) -> None:
        if not self.last_report:
            return
        try:
            report_text = self.last_report.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            QMessageBox.critical(self, "Report Could Not Be Opened", str(exc))
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Veyra Scan - Scan Report")
        dialog.resize(820, 640)
        layout = QVBoxLayout(dialog)
        viewer = QTextBrowser()
        viewer.setReadOnly(True)
        viewer.setOpenExternalLinks(False)
        viewer.anchorClicked.connect(self._open_report_link)
        viewer.setHtml(_summary_html(self.last_summary))
        viewer.setObjectName("reportViewer")
        layout.addWidget(viewer)
        details_button = QPushButton("Show Technical Details")
        details_button.setObjectName("detailsButton")

        def toggle_details() -> None:
            showing_details = details_button.text().startswith("Show")
            if showing_details:
                viewer.setPlainText(report_text)
                details_button.setText("Back to Simple View")
            else:
                viewer.setHtml(_summary_html(self.last_summary))
                details_button.setText("Show Technical Details")

        details_button.clicked.connect(toggle_details)
        layout.addWidget(details_button)
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button, alignment=Qt.AlignRight)
        dialog.setStyleSheet(_stylesheet())
        dialog.exec()

    def _open_report_link(self, url) -> None:
        if str(url.scheme()).lower() != "evidence" or self.last_summary is None:
            return
        try:
            index = int(str(url.path()).strip("/"))
            item = list(self.last_summary.jar_results)[index]
        except (ValueError, IndexError, TypeError):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Evidence - {item.file_name}")
        dialog.resize(860, 680)
        layout = QVBoxLayout(dialog)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Archive / Nested JAR", "Verdict", "Score"])
        root = QTreeWidgetItem([item.file_name, item.verdict, f"{item.risk_score}/100"])
        tree.addTopLevelItem(root)
        _populate_nested_tree(root, item)
        root.setExpanded(True)
        tree.setVisible(bool(item.nested_results))
        layout.addWidget(tree)
        evidence = QTextBrowser()
        evidence.setReadOnly(True)
        evidence.setHtml(_evidence_html(item))
        evidence.setObjectName("reportViewer")
        layout.addWidget(evidence)
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button, alignment=Qt.AlignRight)
        dialog.setStyleSheet(_stylesheet())
        dialog.exec()

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.running:
            answer = QMessageBox.question(self, "Veyra Scan", "A scan is still running. Close anyway?")
            if answer != QMessageBox.Yes:
                event.ignore()
                return
        event.accept()


def _asset_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "xien_control" / "anime_background.png"
    return Path(__file__).resolve().parent / "anime_background.png"


def _stylesheet() -> str:
    return """
        QWidget { font-family: Arial; color: #4b3d45; }
        QFrame#panel { background: transparent; border: none; }
        QLabel#title { font-size: 22px; font-weight: 600; }
        QLabel#subtitle { color: #956a82; font-size: 13px; }
        QPushButton#scanOption {
            background: rgba(255, 243, 248, 155); border: 1px solid rgba(241, 203, 220, 190);
            border-radius: 10px; padding: 0 14px; font-size: 12px; color: #4b3d45;
        }
        QPushButton#scanOption:checked { background: rgba(255, 255, 255, 190); border: 2px solid #b87995; font-weight: 400; color: #95627a; }
        QPushButton#scanOption:hover { background: rgba(255, 255, 255, 180); }
        QLabel#hint, QLabel#status, QLabel#resourceStatus { color: #956a82; font-size: 11px; }
        QLabel#githubLink { color: #a96d88; font-size: 13px; background: transparent; }
        QLabel#privacy { color: #a55d7e; font-size: 10px; background: transparent; }
        QPushButton { background: #b87995; color: white; border: 1px solid #9f637d; border-radius: 2px; min-height: 38px; font-size: 13px; font-weight: 400; padding: 0 18px; }
        QPushButton:hover { background: #ae708c; }
        QPushButton:disabled { background: #dca0bc; }
        QPushButton#reportButton { background: #ffffff; color: #a96d88; border: 1px solid #c58fa7; }
        QProgressBar { border: 1px solid #ead3dd; background: #f5e8ee; border-radius: 0; max-height: 6px; }
        QProgressBar::chunk { background: #b87995; border-radius: 0; }
        QTextBrowser#reportViewer { background: white; color: #3f363b; border: 1px solid #d8cbd1; border-radius: 0; padding: 14px; font-size: 12px; }
        QPushButton#detailsButton { background: #8f6a80; }
    """


def _summary_html(summary) -> str:
    if summary is None:
        return "<h2>Scan Result</h2><p>The visual summary is unavailable. Use technical details.</p>"

    jars = list(summary.jar_results)
    jar_indices = {id(value): index for index, value in enumerate(jars)}
    suspicious = sorted(summary.suspicious_jars, key=lambda item: item.risk_score, reverse=True)
    verified = [item for item in jars if item.modrinth_verified]
    process_findings = [
        finding
        for process in summary.process_results
        for finding in list(process.get("findings", []) or [])
    ]
    serious_process = [
        item for item in process_findings
        if int(item.get("evidence_score", 0) or 0) >= 70
        or (
            str(item.get("severity", "")).lower() in {"critical", "high"}
            and str(item.get("confidence", "medium")).lower() != "low"
        )
    ]
    serious_jars = [item for item in suspicious if item.verdict in {"CRITICAL", "HIGH_RISK"}]
    if serious_jars or serious_process:
        status, color, soft = "Action Recommended", "#b4235a", "#fff0f5"
        message = "Important findings need your attention. Review the highlighted items below."
    elif suspicious or process_findings or summary.mousetweaks_findings or summary.freecam_findings or summary.autoclicker_findings or summary.deleted_mod_findings:
        status, color, soft = "Review Suggested", "#b86a16", "#fff8e8"
        message = "Some signals were found. They are not automatic proof of cheating."
    else:
        status, color, soft = "No Important Findings", "#267a55", "#edf9f3"
        message = "No configured high-risk indicators were detected in this scan."

    cards = (
        _metric_card("Mods scanned", len(jars))
        + _metric_card("Mods to review", len(suspicious), "#b4235a" if suspicious else "#267a55")
        + _metric_card("Modrinth verified", len(verified))
        + _metric_card("Java processes", len(summary.process_results))
    )
    parts = [f"""
    <html><body style='font-family:Arial;color:#3f363b;background:#ffffff'>
    <div style='background:{soft};border:1px solid {color};padding:14px'>
      <div style='font-size:20px;font-weight:600;color:{color}'>{status}</div>
      <div style='margin-top:5px;color:#725465'>{message}</div>
    </div>
    <table width='100%' cellspacing='8' style='margin-top:8px'><tr>{cards}</tr></table>
    """]

    if summary.changed_jars:
        changed_names = [item.file_name for item in jars if item.previous_scan_notes and any("changed" in note for note in item.previous_scan_notes)]
        changed_text = ", ".join(changed_names[:12]) or "One or more previously seen JARs"
        parts.append(f"<div style='background:#fff8e8;border:1px solid #d7b36a;padding:12px;color:#805b18'><b>Hash change warning:</b> {summary.changed_jars} mod(s) changed since the previous scan.<br><span style='font-size:11px'>{escape(changed_text)}</span></div>")
    elif summary.new_jars or summary.removed_jars:
        parts.append(f"<div style='background:#f7f3f5;border:1px solid #d3aabd;padding:10px;color:#725465'><b>History:</b> {summary.new_jars} new mod(s), {summary.removed_jars} removed.</div>")

    if summary.deleted_mod_findings:
        parts.append("<h2 style='color:#a96d88'>Removed Mod Traces</h2>")
        parts.append(f"<div style='background:#fff8e8;border:1px solid #e5cf9e;padding:12px;color:#8b5a18'><b>{len(summary.deleted_mod_findings)} historical trace(s).</b> These records do not prove that a mod is currently loaded.</div>")
        for finding in summary.deleted_mod_findings[:15]:
            location = str(finding.get("path", ""))
            if finding.get("line"):
                location += f" | line {finding.get('line')}"
            parts.append(_finding_card(
                f"TRACE {str(finding.get('confidence', 'low')).upper()}",
                str(finding.get("mod_name", "Historical mod")),
                str(finding.get("message", "Historical mod trace found.")),
                location + " | " + str(finding.get("evidence", "")),
            ))

    if summary.mousetweaks_findings:
        parts.append("<h2 style='color:#9f2f62'>MouseTweaks Finder</h2>")
        parts.append(f"<div style='background:#fff1f5;border:1px solid #d3aabd;padding:12px;color:#8f2857'><b>MouseTweaks detected:</b> {len(summary.mousetweaks_findings)} trace(s) found.</div>")
        for finding in summary.mousetweaks_findings[:20]:
            source = "Instance log" if finding.get("source_type") == "log" else "Mod file"
            location = str(finding.get("path", ""))
            if finding.get("line"):
                location += f" | line {finding.get('line')}"
            parts.append(_finding_card("MOUSETWEAKS", source, str(finding.get("evidence", "Trace found")), location))
        if len(summary.mousetweaks_findings) > 20:
            parts.append(f"<p>+{len(summary.mousetweaks_findings) - 20} more MouseTweaks traces are available in Technical Details.</p>")
    elif "mousetweaks" in summary.completed_categories or "mousetweaks_freecam" in summary.completed_categories:
        parts.append("<h2 style='color:#9f2f62'>MouseTweaks Finder</h2>")
        parts.append("<div style='background:#edf9f3;border:1px solid #b8dac9;padding:12px;color:#267a55'><b>No MouseTweaks traces found.</b> Instance logs and mod contents were checked.</div>")

    if summary.freecam_findings:
        parts.append("<h2 style='color:#a96d88'>Freecam Finder</h2>")
        parts.append(f"<div style='background:#fff1f5;border:1px solid #d3aabd;padding:12px;color:#8f2857'><b>Freecam/FreeLook detected:</b> {len(summary.freecam_findings)} trace(s) found.</div>")
        for finding in summary.freecam_findings[:20]:
            source = "Instance log" if finding.get("source_type") == "log" else "Mod file"
            location = str(finding.get("path", ""))
            if finding.get("line"):
                location += f" | line {finding.get('line')}"
            parts.append(_finding_card("FREECAM", source, str(finding.get("message", "Freecam/FreeLook trace found.")), location + " | " + str(finding.get("evidence", ""))))
    elif "freecam" in summary.completed_categories or "mousetweaks_freecam" in summary.completed_categories:
        parts.append("<h2 style='color:#a96d88'>Freecam Finder</h2>")
        parts.append("<div style='background:#edf9f3;border:1px solid #b8dac9;padding:12px;color:#267a55'><b>No Freecam/FreeLook traces found.</b> Instance logs and mod contents were checked.</div>")

    if summary.autoclicker_findings:
        parts.append("<h2 style='color:#a96d88'>Xray / Clicker / Totem / Mace Finder</h2>")
        parts.append(f"<div style='background:#fff1f5;border:1px solid #d3aabd;padding:12px;color:#8f2857'><b>Xray/Clicker/Auto-Totem/Mace-Swap trace detected:</b> {len(summary.autoclicker_findings)} found.</div>")
        for finding in summary.autoclicker_findings[:20]:
            source = "Instance log" if finding.get("source_type") == "log" else "Mod file"
            location = str(finding.get("path", ""))
            if finding.get("line"):
                location += f" | line {finding.get('line')}"
            parts.append(_finding_card("XRAY / CLICKER / TOTEM / MACE", source, str(finding.get("message", "Xray, AutoClicker, Auto-Totem, or Mace-Swap trace found.")), location + " | " + str(finding.get("evidence", ""))))
    elif "xray_autoclicker" in summary.completed_categories:
        parts.append("<h2 style='color:#a96d88'>Xray / Clicker / Totem / Mace Finder</h2>")
        parts.append("<div style='background:#edf9f3;border:1px solid #b8dac9;padding:12px;color:#267a55'><b>No Xray, AutoClicker, Auto-Totem, or Mace-Swap traces found.</b> Logs, mod contents, and texture packs were checked.</div>")


    if jars:
        parts.append("<h2 style='color:#a96d88'>Minecraft Mods</h2>")
        avg_obfuscation = (sum(item.obfuscation_ratio for item in jars) / len(jars)) if jars else 0
        decoded_total = sum(len(item.decoded_string_hits) for item in jars)
        parts.append(f"<div style='color:#725465;font-size:11px'>Average obfuscation: {avg_obfuscation:.1%} &nbsp;|&nbsp; Decoded strings: {decoded_total} &nbsp;|&nbsp; History: +{summary.new_jars} new, {summary.changed_jars} changed, {summary.removed_jars} removed</div>")
        if not suspicious:
            parts.append("<div style='background:#edf9f3;border:1px solid #b8dac9;padding:12px;color:#267a55'><b>Looks clear.</b> No mods require review.</div>")
        else:
            parts.append("<p>Only mods that need attention are shown here:</p>")
            for item in suspicious[:15]:
                reason = _full_reason(item)
                locations = [f"{m.class_name}{('#' + m.method_name) if m.method_name else ''}" for m in item.detections if m.class_name]
                detail = f"Risk score: {item.risk_score}/100 | Obfuscation: {item.obfuscation_ratio:.1%} | Decoded strings: {len(item.decoded_string_hits)}"
                detail += f" | Confidence: {item.analysis_confidence} | Analysis: {item.analysis_status}"
                sources = sorted({m.source_type for m in item.detections if m.severity in {'medium', 'high', 'critical'}})
                if sources:
                    detail += " | Evidence: " + ", ".join(sources[:5])
                if locations:
                    detail += " | Location: " + ", ".join(dict.fromkeys(locations))[:180]
                if item.deep_audit_entries:
                    detail += f" | Deep audit: {item.deep_audit_entries} entries, {item.deep_audit_valid_class_entries}/{item.deep_audit_class_entries} valid classes"
                    if item.deep_audit_feature_hits:
                        reason += " Deep audit: " + "; ".join(item.deep_audit_feature_hits[:2])
                if item.family_id:
                    detail += f" | Family: {item.family_id} ({item.family_similarity:.0%})"
                if item.opaque_payload_paths:
                    detail += f" | Opaque payloads: {len(item.opaque_payload_paths)} ({item.opaque_payload_high_entropy} high entropy)"
                if item.opaque_payload_formats:
                    detail += " | Hidden formats: " + ", ".join(sorted(set(item.opaque_payload_formats.values())))
                link = f"<br><a style='color:#9f2f62' href='evidence://jar/{jar_indices.get(id(item), 0)}'>Open class / method / mixin evidence</a>"
                parts.append(_finding_card(item.verdict.replace("_", " "), item.file_name, reason, detail, link))
            if len(suspicious) > 15:
                parts.append(f"<p>+{len(suspicious) - 15} more items are available in Technical Details.</p>")

        evidence_items = jars if "manual_jar" in summary.completed_categories else [item for item in jars if item.nested_results]
        if evidence_items:
            parts.append("<h3 style='color:#a96d88'>Archive Evidence / Nested JAR Tree</h3>")
            for item in evidence_items[:20]:
                nested_count = len(item.nested_results)
                parts.append(
                    f"<div style='padding:7px;border-bottom:1px solid #ead3dd'><b>{escape(item.file_name)}</b> "
                    f"<span style='color:#956a82'>({nested_count} nested)</span> — "
                    f"<a style='color:#9f2f62' href='evidence://jar/{jar_indices.get(id(item), 0)}'>Open evidence tree</a></div>"
                )

    if summary.process_results or "javaw_scan" in summary.completed_categories:
        parts.append("<h2 style='color:#a96d88;margin-bottom:4px'>Javaw Scan</h2>")
        parts.append("<div style='color:#956a82;font-size:11px;margin-bottom:10px'>Live JVM memory, runtime JAR, loaded module, open-file and launch-option analysis</div>")
        if not summary.process_results:
            parts.append("<div style='background:#fff8e8;border:1px solid #e5cf9e;padding:12px;color:#8b5a18'><b>Minecraft was not running.</b> No active javaw.exe process could be scanned.</div>")
        else:
            for process in summary.process_results:
                findings = list(process.get("findings", []) or [])
                strong_findings = [item for item in findings if int(item.get("evidence_score", 0) or 0) >= 70]
                review_findings = [item for item in findings if 40 <= int(item.get("evidence_score", 0) or 0) < 70]
                weak_findings = [item for item in findings if int(item.get("evidence_score", 0) or 0) < 40]
                pid = escape(str(process.get("pid", "?")))
                scanned_mb = int(process.get("scanned_bytes", 0) or 0) / 1048576
                readable_mb = int(process.get("readable_bytes_seen", 0) or 0) / 1048576
                working_set_mb = int(process.get("working_set_bytes", 0) or 0) / 1048576
                jar_count = int(process.get("jar_artifacts_seen", 0) or 0)
                region_count = int(process.get("scanned_regions", 0) or 0)
                successful_regions = int(process.get("successful_regions", 0) or 0)
                thread_count = int(process.get("thread_count", 0) or 0)
                parent_name = escape(str(process.get("parent_process_name", "") or "unknown launcher"))
                stop_reason = escape(str(process.get("memory_scan_stop_reason", "") or "completed"))
                coverage_quality = escape(str(process.get("memory_coverage_quality", "") or "Unavailable"))
                read_success = float(process.get("memory_read_success_percent", 0.0) or 0.0)
                sampling_mode = escape(str(process.get("memory_sampling_mode", "") or "unknown"))
                planned_chunks = int(process.get("memory_planned_chunks", 0) or 0)
                completed_chunks = int(process.get("memory_completed_chunks", 0) or 0)
                partial_reads = int(process.get("memory_partial_reads", 0) or 0)
                class_hints = int(process.get("memory_class_hints_seen", 0) or 0)
                class_origins = list(process.get("runtime_class_origins", []) or [])
                private_exec_regions = int(process.get("private_executable_regions", 0) or 0)
                private_exec_mb = int(process.get("private_executable_bytes", 0) or 0) / 1048576
                hidden_pe_regions = list(process.get("hidden_pe_regions", []) or [])
                private_thread_starts = list(process.get("private_exec_thread_starts", []) or [])
                unlisted_images = list(process.get("unlisted_image_regions", []) or [])
                module_integrity_checked = int(process.get("module_integrity_checked", 0) or 0)
                module_disk_mismatches = int(process.get("module_disk_mismatches", 0) or 0)
                runtime_jars_probed = int(process.get("runtime_jars_probed", 0) or 0)
                executable = escape(str(process.get("executable", "") or "Executable path unavailable"))
                started_at = escape(str(process.get("process_started_at", "") or "unknown"))
                parts.append(
                    "<div style='background:#fbf7f9;border:1px solid #e2d5db;padding:13px;margin:10px 0'>"
                    f"<div style='font-size:16px;font-weight:600;color:#6f4e60'>javaw.exe &nbsp; <span style='font-size:11px;font-weight:400;color:#956a82'>PID {pid}</span></div>"
                    f"<div style='font-size:10px;color:#956a82;margin-top:4px'>{executable}</div>"
                    f"<div style='font-size:10px;color:#725465;margin-top:5px'>Parent: {parent_name} &nbsp;|&nbsp; Started: {started_at} &nbsp;|&nbsp; Threads: {thread_count} &nbsp;|&nbsp; Working set: {working_set_mb:.1f} MB</div>"
                    "</div>"
                )
                java_cards = (
                    _metric_card("Memory read", f"{scanned_mb:.0f} MB")
                    + _metric_card("Read success", f"{read_success:.0f}%", "#267a55" if read_success >= 90 else "#b86a16")
                    + _metric_card("Runtime JARs", jar_count)
                    + _metric_card("Strong evidence", len(strong_findings), "#b4235a" if strong_findings else "#267a55")
                )
                parts.append(f"<table width='100%' cellspacing='6'><tr>{java_cards}</tr></table>")
                parts.append(f"<div style='color:#725465;font-size:10px;margin:4px 0 10px'>Coverage: <b>{coverage_quality}</b> | Mode: {sampling_mode} | Chunks: {completed_chunks}/{planned_chunks} | Regions reached: {successful_regions}/{region_count} | {scanned_mb:.1f}/{readable_mb:.1f} MB read/discovered | Partial reads: {partial_reads} | Stop: {stop_reason} | Class-path hints: {class_hints}</div>")
                parts.append(
                    "<div style='background:#f7f3f5;border:1px solid #e2d5db;padding:9px;color:#725465;font-size:10px;margin-bottom:9px'>"
                    f"<b>Runtime provenance:</b> {len(class_origins)} class-to-JAR link(s) &nbsp;|&nbsp; "
                    f"<b>Native map:</b> {private_exec_regions} private executable region(s), {private_exec_mb:.1f} MB &nbsp;|&nbsp; "
                    f"PE candidates: {len(hidden_pe_regions)} &nbsp;|&nbsp; private thread starts: {len(private_thread_starts)} &nbsp;|&nbsp; unlisted images: {len(unlisted_images)}"
                    f"<br><b>Integrity:</b> {module_integrity_checked} loaded PE image(s) checked against disk, {module_disk_mismatches} mismatch(es) &nbsp;|&nbsp; {runtime_jars_probed} active JAR structural probe(s)"
                    "<br><span style='color:#956a82'>Private executable memory alone is expected for JVM JIT code and is not flagged without PE, thread, or loader-list evidence.</span></div>"
                )

                if strong_findings:
                    parts.append(f"<div style='background:#fff0f5;border-left:4px solid #b4235a;padding:11px;color:#7f244b'><b>{len(strong_findings)} strong evidence item(s).</b> These have correlated, known-artifact, or runtime-only evidence and should be reviewed first.</div>")
                elif review_findings:
                    parts.append(f"<div style='background:#fff8e8;border-left:4px solid #b86a16;padding:11px;color:#805b18'><b>No strong correlation.</b> {len(review_findings)} contextual item(s) remain for manual review.</div>")
                elif weak_findings:
                    parts.append(f"<div style='background:#f7f3f5;border-left:4px solid #a98d9b;padding:11px;color:#725465'><b>Only weak signals were found.</b> They are shown separately and do not count as strong evidence.</div>")
                else:
                    parts.append("<div style='background:#edf9f3;border-left:4px solid #267a55;padding:11px;color:#267a55'><b>No indicators matched.</b> Memory, runtime artifacts and launch options were checked.</div>")
                runtime_only = list(process.get("runtime_only_jars", []) or [])
                memory_jars = list(process.get("memory_jar_paths", []) or [])
                jar_details = {str(item.get("path", "")): item for item in list(process.get("runtime_jar_details", []) or [])}
                if runtime_only:
                    runtime_lines = []
                    for path in runtime_only[:12]:
                        detail = jar_details.get(str(path), {})
                        sources = ", ".join(str(value) for value in detail.get("sources", []) or [])
                        digest = str(detail.get("sha256", "") or "")
                        suffix = (f" | source: {sources}" if sources else "") + (f" | SHA-256: {digest[:16]}..." if digest else "")
                        probe = detail.get("structural_probe", {}) if isinstance(detail, dict) else {}
                        if isinstance(probe, dict) and probe.get("status") == "complete":
                            suffix += f" | loader probe: opaque={probe.get('high_entropy_opaque_payloads', 0)}, defineClass={probe.get('direct_class_loader', False)}, native={probe.get('native_memory_bridge', False)}"
                        runtime_lines.append(escape(str(path) + suffix))
                    parts.append("<div style='background:#fff0f5;border:1px solid #d3aabd;padding:10px;color:#8f2857'><b>Runtime-only JARs:</b><br>" + "<br>".join(runtime_lines) + "</div>")
                elif memory_jars:
                    parts.append(f"<div style='color:#725465;font-size:11px'>Disk-memory comparison: {len(memory_jars)} JAR path(s) recovered from JVM memory; no runtime-only mod candidate remained.</div>")

                if class_origins:
                    ordered_origins = sorted(
                        class_origins,
                        key=lambda item: (item.get("class_present_on_disk") is not False, str(item.get("class_name", "")).lower()),
                    )
                    parts.append("<h3 style='font-size:13px;color:#7d5a6d;margin:14px 0 5px'>Runtime class → source JAR</h3>")
                    parts.append("<div style='background:#fcfafb;border:1px solid #e2d5db;padding:7px'>")
                    for origin in ordered_origins[:12]:
                        disk_state = origin.get("class_present_on_disk")
                        state = "verified on disk" if disk_state is True else "disk mismatch" if disk_state is False else "memory source only"
                        state_color = "#267a55" if disk_state is True else "#b4235a" if disk_state is False else "#956a82"
                        class_name = escape(str(origin.get("class_name", "Unknown class")))
                        jar_name = escape(Path(str(origin.get("jar_path", "Unknown JAR"))).name or str(origin.get("jar_path", "Unknown JAR")))
                        address = escape(str(origin.get("address", "")))
                        parts.append(f"<div style='padding:5px;border-bottom:1px solid #eee4e9'><b>{class_name}</b> → {jar_name} <span style='color:{state_color}'>({state})</span> <span style='color:#a98d9b;font-size:9px'>{address}</span></div>")
                    if len(class_origins) > 12:
                        parts.append(f"<div style='padding:5px;color:#956a82'>+{len(class_origins) - 12} more class origins are retained in Technical Details.</div>")
                    parts.append("</div>")

                shown = 0
                for heading, group, heading_color in (
                    ("Strong / correlated evidence", strong_findings, "#b4235a"),
                    ("Contextual review", review_findings, "#b86a16"),
                    ("Weak memory or path signals", weak_findings, "#8b7581"),
                ):
                    if not group:
                        continue
                    parts.append(f"<h3 style='font-size:13px;color:{heading_color};margin:14px 0 5px'>{heading} <span style='font-weight:400'>({len(group)})</span></h3>")
                    group_limit = 8 if heading.startswith("Strong") else 5 if heading.startswith("Contextual") else 3
                    for finding in group[:group_limit]:
                        detail = str(finding.get("path") or finding.get("address") or "Memory match")
                        score = int(finding.get("evidence_score", 0) or 0)
                        detail += f" | Evidence: {score}/100 | Confidence: {str(finding.get('confidence', 'medium')).title()} | Detector: {str(finding.get('detector', 'unknown'))}"
                        if finding.get("memory_type") or finding.get("protection"):
                            detail += f" | Region: {finding.get('memory_type', 'unknown')} {finding.get('protection', '')} @ {finding.get('region_base', '')}"
                        level = "WEAK SIGNAL" if score < 40 else str(finding.get("severity", "info")).upper()
                        parts.append(_finding_card(level, str(finding.get("indicator", "Finding")), str(finding.get("explanation", "Indicator matched.")), detail))
                        shown += 1
                if len(findings) > shown:
                    parts.append(f"<p style='color:#956a82;font-size:11px'>+{len(findings) - shown} more findings are available in Technical Details.</p>")

    if not jars and not summary.process_results and "mousetweaks" not in summary.completed_categories and "freecam" not in summary.completed_categories and "mousetweaks_freecam" not in summary.completed_categories and "xray_autoclicker" not in summary.completed_categories:
        parts.append("<h2>Scan Summary</h2><p>No supported items or active Java processes were available for this scan.</p>")
    parts.append("<p style='margin-top:24px;color:#956a82;font-size:11px'>A detection is a review signal, not automatic proof. Use Technical Details for paths, hashes, and full evidence.</p></body></html>")
    return "".join(parts)


def _metric_card(label: str, value: object, color: str = "#a96d88") -> str:
    return f"<td align='center' style='background:#f7f3f5;border:1px solid #ddd3d8;padding:10px'><div style='font-size:20px;font-weight:600;color:{color}'>{value}</div><div style='font-size:10px;color:#777'>{escape(label)}</div></td>"


def _finding_card(level: str, title: str, explanation: str, detail: str, extra_html: str = "") -> str:
    severe = level.upper() in {"CRITICAL", "HIGH", "HIGH RISK"}
    color = "#b4235a" if severe else "#b86a16"
    background = "#fff0f5" if severe else "#fff8e8"
    return f"<div style='background:{background};border-left:4px solid {color};padding:11px;margin:8px 0'><b style='color:{color}'>{escape(level)}</b> &nbsp; <b>{escape(title)}</b><br><span>{escape(explanation)}</span><br><span style='font-size:10px;color:#956a82'>{escape(detail)}</span>{extra_html}</div>"


def _populate_nested_tree(parent: QTreeWidgetItem, item) -> None:
    for child in list(item.nested_results or []):
        label = child.nested_path or child.file_name
        node = QTreeWidgetItem([str(label), str(child.verdict), f"{child.risk_score}/100"])
        parent.addChild(node)
        _populate_nested_tree(node, child)


def _evidence_html(item) -> str:
    parts = [
        "<html><body style='font-family:Arial;color:#3f363b;background:#ffffff'>",
        f"<h2 style='color:#a96d88'>{escape(item.file_name)}</h2>",
        f"<p><b>{escape(item.verdict)}</b> &nbsp; {item.risk_score}/100 &nbsp; | &nbsp; SHA-256: {escape(item.sha256)}</p>",
        f"<p><b>Path:</b> {escape(str(item.path))}</p>",
    ]
    if item.mixin_targets:
        parts.append("<h3>Mixin targets</h3><ul>")
        for class_name, targets in sorted(item.mixin_targets.items())[:80]:
            parts.append(f"<li><b>{escape(str(class_name))}</b> → {escape(', '.join(sorted(targets)))}</li>")
        parts.append("</ul>")
    if item.family_id or item.opaque_payload_paths:
        parts.append("<h3>Loader / payload structure</h3><div style='background:#fcf7f9;border:1px solid #e2d5db;padding:9px'>")
        if item.family_id:
            parts.append(f"<b>Family:</b> {escape(item.family_id)} ({item.family_similarity:.0%})<br>")
        if item.opaque_payload_paths:
            parts.append(f"<b>Opaque resources:</b> {len(item.opaque_payload_paths)} / {item.opaque_payload_bytes} bytes; high entropy={item.opaque_payload_high_entropy}; zero-filled={item.opaque_payload_zero_filled}<br>")
            for path in item.opaque_payload_paths[:20]:
                payload_format = item.opaque_payload_formats.get(path, "high-entropy/opaque")
                parts.append(f"<span style='font-size:10px'>{escape(path)} â€” {escape(payload_format)}</span><br>")
        parts.append("</div>")
    parts.append("<h3>Detections</h3>")
    if not item.detections:
        parts.append("<p>No configured detections.</p>")
    else:
        for detection in item.detections[:150]:
            location = detection.class_name or "Archive/resource"
            if detection.method_name:
                location += f"#{detection.method_name}"
            parts.append(
                "<div style='border-left:3px solid #b87995;background:#f9f4f6;padding:9px;margin:7px 0'>"
                f"<b>{escape(detection.severity.upper())} — {escape(detection.rule_name)}</b><br>"
                f"<span>{escape(detection.explanation)}</span><br>"
                f"<span style='font-size:10px;color:#956a82'>Class/method: {escape(location)} | "
                f"Matched constant: {escape(detection.matched_keyword)} | Source: {escape(detection.source_type)} | "
                f"Evidence: {escape(detection.evidence_preview)}</span></div>"
            )
    if item.nested_results:
        parts.append("<h3>Embedded nested JARs</h3><p>Use the expandable archive tree above to inspect the hierarchy.</p>")
    parts.append("</body></html>")
    return "".join(parts)


def _full_reason(item) -> str:
    """Turn raw rule output into a complete, readable explanation card."""
    parts: list[str] = []
    for detection in list(item.detections or [])[:4]:
        text = (detection.explanation or detection.rule_name or "Indicator matched").strip().rstrip(".")
        location = detection.class_name or ""
        if detection.method_name:
            location += f"#{detection.method_name}"
        if location:
            text += f" (location: {location})"
        parts.append(text)
    if not parts:
        parts.extend(item.why_flagged[:3] or item.risk_reasons[:3] or [report_reason(item)])
    return "; ".join(dict.fromkeys(parts))


def launch_gui() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    window = XienControlGUI()
    window.show()
    return app.exec()
