from __future__ import annotations

import base64
import datetime as dt
import zipfile

from xien_control.archive_scanner import ArchiveScanner
from xien_control.script_analyzer import ScriptAnalyzer
from xien_control.static_models import FileInventoryItem


def test_script_analyzer_detects_referenced_exe_and_encoded_line(tmp_path):
    script = tmp_path / "launch.cmd"
    encoded = base64.b64encode(b"A" * 220).decode("ascii")
    script.write_text(
        "\n".join(
            [
                r"start C:\Users\k\AppData\Local\Temp\runner.exe",
                "powershell -EncodedCommand " + encoded,
            ]
        ),
        encoding="utf-8",
    )
    item = _item(script, "SCRIPT_CMD", "STARTUP")

    result = ScriptAnalyzer().analyze(item)

    assert result.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}
    assert result.referenced_paths
    assert any("encoded-looking" in evidence for evidence in result.evidence)


def test_archive_scanner_detects_nested_application_files(tmp_path):
    archive = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("tools/runner.exe", b"MZ")
        zf.writestr("mods/client.jar", b"PK\x03\x04")
    item = _item(archive, "ARCHIVE_ZIP", "USER_DOWNLOADS")

    result = ArchiveScanner().analyze(item)

    assert result.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}
    assert any("runner.exe" in nested for nested in result.nested_items)
    assert any("nested item" in evidence for evidence in result.evidence)


def _item(path, file_type: str, folder: str) -> FileInventoryItem:
    modified = dt.datetime(2026, 5, 22, 12, 0, 0)
    return FileInventoryItem(
        path=path,
        file_name=path.name,
        extension=path.suffix,
        file_type=file_type,
        size_bytes=path.stat().st_size,
        created_time=modified,
        last_modified=modified,
        folder_category=folder,
    )
