from __future__ import annotations

import datetime as dt
from pathlib import Path

from xien_control.deep_analysis_queue import build_deep_analysis_queue
from xien_control.static_models import FileInventoryItem


def test_deep_queue_prioritizes_user_files_and_skips_old_program_files_pe():
    now = dt.datetime(2026, 5, 22, 12, 0, 0)
    old = now - dt.timedelta(days=30)
    items = [
        _item(Path(r"C:\Program Files\Vendor\app.exe"), "PE_EXE", "PROGRAM_FILES", old),
        _item(Path(r"C:\Users\k\AppData\Local\helper.dll"), "PE_DLL", "APPDATA_LOCAL", old),
        _item(Path(r"C:\Users\k\Downloads\client.jar"), "JAVA_ARCHIVE", "USER_DOWNLOADS", old),
        _item(Path(r"C:\Users\k\Desktop\run.ps1"), "SCRIPT_PS1", "USER_DESKTOP", old),
    ]

    queue = build_deep_analysis_queue(items, now=now)
    queued = {item.file_name for item in queue.items}

    assert "app.exe" not in queued
    assert {"helper.dll", "client.jar", "run.ps1"}.issubset(queued)
    assert queue.skipped_low_priority == 1


def _item(path: Path, file_type: str, folder: str, modified: dt.datetime) -> FileInventoryItem:
    return FileInventoryItem(
        path=path,
        file_name=path.name,
        extension=path.suffix,
        file_type=file_type,
        size_bytes=100,
        created_time=modified,
        last_modified=modified,
        folder_category=folder,
    )
