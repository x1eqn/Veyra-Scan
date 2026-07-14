from __future__ import annotations

import datetime as dt
import ntpath

from .file_classifier import is_archive_type, is_installer_type, is_pe_type, is_script_type, is_shortcut_type
from .location_baseline import LocationBaseline
from .static_models import DeepAnalysisQueue, FileInventoryItem


SENSITIVE_FOLDERS = {
    "USER_DOWNLOADS",
    "USER_DESKTOP",
    "USER_DOCUMENTS",
    "APPDATA_LOCAL",
    "APPDATA_ROAMING",
    "TEMP",
    "STARTUP",
    "MINECRAFT_LAUNCHER_FOLDER",
    "GAME_FOLDER",
    "UNKNOWN_USER_FOLDER",
}


def build_deep_analysis_queue(items: list[FileInventoryItem], baseline: LocationBaseline | None = None, now: dt.datetime | None = None) -> DeepAnalysisQueue:
    now = now or dt.datetime.now().replace(microsecond=0)
    queue = DeepAnalysisQueue()
    for item in items:
        item.file_name = _display_name(item.path, item.file_name)
        deep, reason = _should_deep_analyze(item, baseline, now)
        item.deep_candidate = deep
        item.deep_reason = reason
        item.analyzer_name = _analyzer_name(item.file_type)
        item.analysis_priority = _priority_for(item, reason, now)
        if deep:
            queue.items.append(item)
            queue.reasons[reason] = queue.reasons.get(reason, 0) + 1
        else:
            queue.skipped_low_priority += 1
    return queue


def _should_deep_analyze(item: FileInventoryItem, baseline: LocationBaseline | None, now: dt.datetime) -> tuple[bool, str]:
    if item.file_type == "JAVA_ARCHIVE":
        return True, "java archive"
    if item.folder_category in SENSITIVE_FOLDERS:
        return True, f"sensitive folder: {item.folder_category}"
    if baseline and baseline.is_new_location(item) and item.folder_category not in {"SYSTEM_WINDOWS", "PROGRAM_FILES"}:
        return True, "new application location"
    age_hours = (now - item.last_modified).total_seconds() / 3600
    if age_hours <= 72 and item.folder_category not in {"SYSTEM_WINDOWS"}:
        return True, "recently modified"
    if item.file_type in {"PE_SCR", "PE_CPL"}:
        return True, "rare PE type"
    if is_script_type(item.file_type) or is_shortcut_type(item.file_type) or is_installer_type(item.file_type) or is_archive_type(item.file_type):
        return item.folder_category != "SYSTEM_WINDOWS", "static app-related file"
    if is_pe_type(item.file_type) and item.folder_category == "PROGRAM_FILES":
        return False, "signed baseline candidate"
    return False, "low priority inventory item"


def _analyzer_name(file_type: str) -> str:
    if file_type == "JAVA_ARCHIVE":
        return "jar_scanner"
    if is_pe_type(file_type):
        return "pe_analyzer"
    if is_script_type(file_type):
        return "script_analyzer"
    if is_shortcut_type(file_type):
        return "shortcut_analyzer"
    if is_installer_type(file_type):
        return "installer_analyzer"
    if is_archive_type(file_type):
        return "archive_scanner"
    return "inventory"


def _display_name(path, current: str) -> str:
    text = str(path)
    if "\\" in text:
        return ntpath.basename(text) or current
    return current


def _priority_for(item: FileInventoryItem, reason: str, now: dt.datetime) -> str:
    if item.folder_category == "STARTUP":
        return "URGENT"
    if item.folder_category in {"TEMP", "APPDATA_LOCAL", "APPDATA_ROAMING"}:
        return "HIGH"
    if "new application location" in reason or "recently modified" in reason or item.file_type in {"PE_SCR", "PE_CPL"}:
        return "HIGH"
    if item.folder_category in {"USER_DOWNLOADS", "USER_DESKTOP", "MINECRAFT_LAUNCHER_FOLDER"}:
        return "NORMAL"
    if (now - item.last_modified).total_seconds() <= 24 * 3600:
        return "NORMAL"
    return "LOW"
