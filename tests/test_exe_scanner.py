from __future__ import annotations

from xien_control.exe_scanner import WindowsExeScanner

from .pe_fixtures import high_entropy_bytes, minimal_pe_bytes


def test_exe_scanner_handles_invalid_exe_without_crash(tmp_path):
    path = tmp_path / "broken.exe"
    path.write_bytes(b"not a real executable")

    summary = WindowsExeScanner(cache_dir=tmp_path / "cache", roots=[tmp_path], enable_cache=False).scan()

    assert summary.scanned_exes == 1
    assert summary.results[0].pe.mz_header is False


def test_duplicate_hash_detection(tmp_path):
    data = minimal_pe_bytes(high_entropy_bytes())
    first = tmp_path / "one.exe"
    second = tmp_path / "two.exe"
    first.write_bytes(data)
    second.write_bytes(data)

    summary = WindowsExeScanner(cache_dir=tmp_path / "cache", roots=[tmp_path], enable_cache=False).scan()

    assert summary.scanned_exes == 2
    assert summary.duplicate_hashes == 2
    assert all(item.duplicate_status for item in summary.results)


def test_exe_cache_reuse(tmp_path):
    path = tmp_path / "cached.exe"
    path.write_bytes(minimal_pe_bytes())
    scanner = WindowsExeScanner(cache_dir=tmp_path / "cache", roots=[tmp_path])

    first = scanner.scan()
    second = scanner.scan()

    assert first.results[0].cache_reused is False
    assert second.results[0].cache_reused is True
