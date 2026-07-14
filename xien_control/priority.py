from __future__ import annotations

import datetime as dt

from .static_models import StaticAnalysisResult


def assign_priority(result: StaticAnalysisResult, newly_seen: bool = False, linked_from_startup: bool = False, archive_nested: bool = False) -> None:
    if linked_from_startup:
        result.priority = "URGENT"
        return
    if result.folder_category == "STARTUP":
        result.priority = "URGENT" if result.review else "HIGH"
        return
    if archive_nested and result.review:
        result.priority = "HIGH"
        return
    if result.folder_category in {"TEMP", "APPDATA_LOCAL", "APPDATA_ROAMING"} and result.review:
        result.priority = "HIGH"
        return
    if newly_seen and result.folder_category in {"USER_DOWNLOADS", "USER_DESKTOP", "UNKNOWN_USER_FOLDER"}:
        result.priority = "HIGH" if result.review else "NORMAL"
        return
    if _recent(result.last_modified, 24) and result.review:
        result.priority = "HIGH"
        return
    if result.folder_category in {"SYSTEM_WINDOWS", "PROGRAM_FILES"} and not result.review:
        result.priority = "LOW"
        return
    result.priority = result.priority or "NORMAL"


def _recent(value: dt.datetime, hours: int) -> bool:
    return (dt.datetime.now().replace(microsecond=0) - value).total_seconds() <= hours * 3600
