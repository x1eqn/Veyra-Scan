from __future__ import annotations

from xien_control.inventory import InventoryScanner


def test_inventory_finds_supported_files_and_skips_unknown(tmp_path):
    (tmp_path / "app.exe").write_bytes(b"MZ")
    (tmp_path / "lib.dll").write_bytes(b"MZ")
    (tmp_path / "run.ps1").write_text("Write-Host test", encoding="utf-8")
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04")
    (tmp_path / "notes.txt").write_text("ignore", encoding="utf-8")

    result = InventoryScanner(roots=[tmp_path]).scan()
    names = {item.file_name for item in result.items}

    assert {"app.exe", "lib.dll", "run.ps1", "archive.zip"}.issubset(names)
    assert "notes.txt" not in names
    assert result.stats.supported_files == 4
