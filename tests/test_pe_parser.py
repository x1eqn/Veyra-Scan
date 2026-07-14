from __future__ import annotations

from xien_control.pe_parser import parse_pe_bytes

from .pe_fixtures import high_entropy_bytes, minimal_pe_bytes


def test_invalid_exe_does_not_crash():
    info = parse_pe_bytes(b"not an exe")

    assert info.mz_header is False
    assert info.pe_signature is False
    assert info.parse_warnings


def test_mz_without_pe_signature_does_not_crash():
    data = b"MZ" + b"\x00" * 128

    info = parse_pe_bytes(data)

    assert info.mz_header is True
    assert info.pe_signature is False


def test_minimal_pe_header_and_high_entropy_section():
    data = minimal_pe_bytes(high_entropy_bytes(), section_name=b".packed")

    info = parse_pe_bytes(data)

    assert info.mz_header is True
    assert info.pe_signature is True
    assert info.architecture == "x64"
    assert info.subsystem == "console"
    assert info.sections[0].name == ".packed"
    assert info.sections[0].entropy >= 7.0
    assert info.unusual_sections
