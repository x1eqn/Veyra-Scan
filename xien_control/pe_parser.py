from __future__ import annotations

import datetime as dt
import hashlib
import re
import struct
from pathlib import Path

from .exe_models import PeInfo, PeSectionInfo
from .pe_entropy import entropy
from .pe_strings import extract_pe_strings, parse_version_info_from_strings


MACHINE_TYPES = {
    0x014C: ("I386", "x86"),
    0x8664: ("AMD64", "x64"),
    0x01C4: ("ARM", "arm"),
    0xAA64: ("ARM64", "arm64"),
}

SUBSYSTEMS = {
    1: "native",
    2: "windows gui",
    3: "console",
    7: "posix",
    9: "windows ce",
    10: "efi application",
    11: "efi boot",
    12: "efi runtime",
    13: "efi rom",
    14: "xbox",
    16: "boot application",
}

SECTION_CHARACTERISTICS = {
    "executable": 0x20000000,
    "readable": 0x40000000,
    "writable": 0x80000000,
}

STANDARD_SECTIONS = {
    ".text",
    ".rdata",
    ".data",
    ".pdata",
    ".rsrc",
    ".reloc",
    ".idata",
    ".edata",
    ".bss",
    ".tls",
    ".xdata",
    "code",
    "data",
    "bss",
}


def parse_pe(path: Path, max_string_bytes: int = 8 * 1024 * 1024, max_file_bytes: int = 96 * 1024 * 1024) -> PeInfo:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            data = fh.read(max_file_bytes if size > max_file_bytes else size)
    except OSError as exc:
        info = PeInfo()
        info.parse_warnings.append(f"read failed: {exc}")
        return info
    info = parse_pe_bytes(data, max_string_bytes=max_string_bytes)
    if size > len(data):
        info.parse_warnings.append(f"limited large-file PE read: {len(data)}/{size} bytes")
    return info


def parse_pe_bytes(data: bytes, max_string_bytes: int = 8 * 1024 * 1024) -> PeInfo:
    info = PeInfo()
    if len(data) < 64:
        info.parse_warnings.append("file too small for MZ header")
        return info
    info.mz_header = data[:2] == b"MZ"
    if not info.mz_header:
        info.parse_warnings.append("missing MZ header")
        return info
    try:
        pe_offset = _u32(data, 0x3C)
        if pe_offset <= 0 or pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            info.parse_warnings.append("missing PE signature")
            return info
        info.pe_signature = True
        coff = pe_offset + 4
        machine = _u16(data, coff)
        machine_name, architecture = MACHINE_TYPES.get(machine, (f"0x{machine:04X}", "unknown"))
        info.machine_type = machine_name
        info.architecture = architecture
        info.number_of_sections = _u16(data, coff + 2)
        timestamp = _u32(data, coff + 4)
        if timestamp:
            info.compile_timestamp = dt.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")
        optional_size = _u16(data, coff + 16)
        info.characteristics = _u16(data, coff + 18)
        optional = coff + 20
        magic = _u16(data, optional)
        is_pe32_plus = magic == 0x20B
        if magic not in {0x10B, 0x20B}:
            info.parse_warnings.append(f"unknown optional header magic 0x{magic:04X}")
            return info
        info.entry_point = _u32(data, optional + 16)
        info.image_base = _u64(data, optional + 24) if is_pe32_plus else _u32(data, optional + 28)
        subsystem_offset = optional + (88 if is_pe32_plus else 68)
        subsystem = _u16(data, subsystem_offset) if subsystem_offset + 2 <= len(data) else 0
        info.subsystem = SUBSYSTEMS.get(subsystem, "unknown")
        data_directory_start = optional + (112 if is_pe32_plus else 96)
        directories = _read_data_directories(data, data_directory_start, optional + optional_size)
        section_offset = optional + optional_size
        info.sections = _read_sections(data, section_offset, info.number_of_sections)
        info.rich_header_present = b"Rich" in data[:4096]
        info.overlay_offset, info.overlay_size = _overlay_info(data, info.sections, directories)
        info.debug_directory_present = bool(directories.get(6, (0, 0))[0])
        info.relocation_table_present = bool(directories.get(5, (0, 0))[0])
        info.exception_table_present = bool(directories.get(3, (0, 0))[0])
        info.certificate_table_present = bool(directories.get(4, (0, 0))[0])
        info.load_config_present = bool(directories.get(10, (0, 0))[0])
        info.bound_imports_present = bool(directories.get(11, (0, 0))[0])
        info.delay_import_table_present = bool(directories.get(13, (0, 0))[0])
        info.clr_header_present = bool(directories.get(14, (0, 0))[0])
        info.tls_callbacks_present = _tls_present(data, info.sections, directories.get(9, (0, 0)), is_pe32_plus)
        _read_imports(data, info, directories.get(1, (0, 0)), is_pe32_plus)
        _read_exports(data, info, directories.get(0, (0, 0)))
        _read_resources(data, info, directories.get(2, (0, 0)), max_string_bytes)
        _read_debug_strings(data, info)
        _read_dotnet_hints(data, info)
        info.imphash = _simple_imphash(info.imported_dlls, info.imported_functions)
        info.permission_summary = _permission_summary(info.sections)
        info.package_type = _detect_package_type(data, info)
    except (IndexError, struct.error, ValueError, OverflowError) as exc:
        info.parse_warnings.append(f"parse failed: {exc}")
    return info


def _read_sections(data: bytes, offset: int, count: int) -> list[PeSectionInfo]:
    sections: list[PeSectionInfo] = []
    for index in range(min(count, 96)):
        cursor = offset + index * 40
        if cursor + 40 > len(data):
            break
        raw_name = data[cursor : cursor + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("utf-8", errors="replace") or f"section_{index}"
        virtual_size = _u32(data, cursor + 8)
        virtual_address = _u32(data, cursor + 12)
        raw_size = _u32(data, cursor + 16)
        raw_pointer = _u32(data, cursor + 20)
        characteristics = _u32(data, cursor + 36)
        raw = data[raw_pointer : raw_pointer + raw_size] if raw_pointer < len(data) else b""
        lower_name = name.lower()
        unusual = (
            lower_name not in STANDARD_SECTIONS
            and not lower_name.startswith((".debug", ".00cfg"))
            and not lower_name.startswith("upx")
        )
        sections.append(
            PeSectionInfo(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_size=raw_size,
                raw_pointer=raw_pointer,
                entropy=entropy(raw[:4 * 1024 * 1024]),
                executable=bool(characteristics & SECTION_CHARACTERISTICS["executable"]),
                readable=bool(characteristics & SECTION_CHARACTERISTICS["readable"]),
                writable=bool(characteristics & SECTION_CHARACTERISTICS["writable"]),
                unusual_name=unusual,
            )
        )
    return sections


def _read_imports(data: bytes, info: PeInfo, directory: tuple[int, int], is_pe32_plus: bool) -> None:
    rva, size = directory
    offset = _rva_to_offset(rva, info.sections)
    if not rva or offset is None:
        return
    thunk_size = 8 if is_pe32_plus else 4
    limit = min(offset + max(size, 20), len(data))
    cursor = offset
    dlls: list[str] = []
    functions: list[str] = []
    descriptors = 0
    while cursor + 20 <= limit + 2048 and cursor + 20 <= len(data) and descriptors < 512:
        original_first_thunk = _u32(data, cursor)
        _time_date_stamp = _u32(data, cursor + 4)
        _forwarder_chain = _u32(data, cursor + 8)
        name_rva = _u32(data, cursor + 12)
        first_thunk = _u32(data, cursor + 16)
        cursor += 20
        descriptors += 1
        if not any((original_first_thunk, name_rva, first_thunk)):
            break
        name_offset = _rva_to_offset(name_rva, info.sections)
        if name_offset is None:
            continue
        dll_name = _cstring(data, name_offset, 160).lower()
        if dll_name:
            dlls.append(dll_name)
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = _rva_to_offset(thunk_rva, info.sections)
        if thunk_offset is None:
            continue
        for _ in range(2048):
            if thunk_offset + thunk_size > len(data):
                break
            thunk_value = _u64(data, thunk_offset) if is_pe32_plus else _u32(data, thunk_offset)
            thunk_offset += thunk_size
            if thunk_value == 0:
                break
            ordinal_mask = 0x8000000000000000 if is_pe32_plus else 0x80000000
            if thunk_value & ordinal_mask:
                functions.append(f"{dll_name}!ordinal")
                continue
            hint_name_offset = _rva_to_offset(int(thunk_value), info.sections)
            if hint_name_offset is None or hint_name_offset + 2 >= len(data):
                continue
            function_name = _cstring(data, hint_name_offset + 2, 220)
            if function_name:
                functions.append(f"{dll_name}!{function_name}")
    info.imported_dlls = _unique(dlls, 256)
    info.imported_functions = _unique(functions, 2000)
    info.import_count = len(info.imported_functions)


def _read_exports(data: bytes, info: PeInfo, directory: tuple[int, int]) -> None:
    rva, _size = directory
    offset = _rva_to_offset(rva, info.sections)
    if not rva or offset is None or offset + 40 > len(data):
        return
    try:
        number_of_names = _u32(data, offset + 24)
        names_rva = _u32(data, offset + 32)
        names_offset = _rva_to_offset(names_rva, info.sections)
        info.export_count = number_of_names
        if names_offset is None:
            return
        names: list[str] = []
        for index in range(min(number_of_names, 200)):
            item_offset = names_offset + index * 4
            if item_offset + 4 > len(data):
                break
            name_offset = _rva_to_offset(_u32(data, item_offset), info.sections)
            if name_offset is not None:
                value = _cstring(data, name_offset, 220)
                if value:
                    names.append(value)
        info.exported_names = names
    except (IndexError, ValueError, struct.error):
        return


def _read_resources(data: bytes, info: PeInfo, directory: tuple[int, int], max_string_bytes: int) -> None:
    rva, size = directory
    if rva and size:
        offset = _rva_to_offset(rva, info.sections)
        if offset is not None:
            resource_blob = data[offset : min(len(data), offset + min(size, max_string_bytes))]
            lower = resource_blob.lower()
            info.manifest_present = b"requestedexecutionlevel" in lower or b"assemblyidentity" in lower
            info.icon_present = b"icon" in lower or b"\x03\x00\x00\x00" in resource_blob[:4096]
            strings = extract_pe_strings(resource_blob, limit=2500)
            info.version_info.update(parse_version_info_from_strings(strings))
    if not info.version_info:
        sample = data[: min(len(data), max_string_bytes)]
        strings = extract_pe_strings(sample, limit=2500)
        info.version_info.update(parse_version_info_from_strings(strings))
        joined = "\n".join(strings[:1000]).lower()
        info.manifest_present = info.manifest_present or "requestedexecutionlevel" in joined or "assemblyidentity" in joined


def _read_data_directories(data: bytes, offset: int, limit: int) -> dict[int, tuple[int, int]]:
    out: dict[int, tuple[int, int]] = {}
    cursor = offset
    for index in range(16):
        if cursor + 8 > len(data) or cursor + 8 > limit:
            break
        out[index] = (_u32(data, cursor), _u32(data, cursor + 4))
        cursor += 8
    return out


def _rva_to_offset(rva: int, sections: list[PeSectionInfo]) -> int | None:
    if rva <= 0:
        return None
    for section in sections:
        size = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + size:
            return section.raw_pointer + (rva - section.virtual_address)
    if rva < 4096:
        return rva
    return None


def _overlay_info(data: bytes, sections: list[PeSectionInfo], directories: dict[int, tuple[int, int]]) -> tuple[int, int]:
    end = 0
    for section in sections:
        if section.raw_pointer and section.raw_size:
            end = max(end, section.raw_pointer + section.raw_size)
    cert_offset, cert_size = directories.get(4, (0, 0))
    if cert_offset and cert_size:
        end = max(end, cert_offset + cert_size)
    return (end, max(0, len(data) - end)) if end else (0, 0)


def _tls_present(data: bytes, sections: list[PeSectionInfo], directory: tuple[int, int], is_pe32_plus: bool) -> bool:
    rva, _size = directory
    offset = _rva_to_offset(rva, sections)
    if not rva or offset is None:
        return False
    callback_offset = offset + (24 if is_pe32_plus else 12)
    if callback_offset + (8 if is_pe32_plus else 4) > len(data):
        return False
    value = _u64(data, callback_offset) if is_pe32_plus else _u32(data, callback_offset)
    return value != 0


def _read_debug_strings(data: bytes, info: PeInfo) -> None:
    text = data[: min(len(data), 12 * 1024 * 1024)].decode("utf-8", errors="ignore")
    match = re.search(r"([A-Za-z]:\\[^'\r\n\x00]+?\.pdb)", text, flags=re.IGNORECASE)
    if not match:
        text16 = data[: min(len(data), 12 * 1024 * 1024)].decode("utf-16le", errors="ignore")
        match = re.search(r"([A-Za-z]:\\[^'\r\n\x00]+?\.pdb)", text16, flags=re.IGNORECASE)
    if match:
        info.pdb_path = match.group(1)[:220]


def _read_dotnet_hints(data: bytes, info: PeInfo) -> None:
    sample = data[: min(len(data), 16 * 1024 * 1024)]
    lower = sample.lower()
    info.dotnet_metadata_present = info.clr_header_present or b"bsjb" in sample or b"#~" in sample or b"#strings" in lower or any(dll == "mscoree.dll" for dll in info.imported_dlls)
    if not info.dotnet_metadata_present:
        return
    strings = extract_pe_strings(sample, limit=4000)
    refs = []
    types = []
    for value in strings:
        if value in {"mscorlib", "System", "System.Core", "System.Windows.Forms", "PresentationFramework", "Microsoft.CSharp"}:
            refs.append(value)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_.]+$", value) and "." in value and len(value) <= 120:
            types.append(value)
    info.dotnet_references = _unique(refs, 20)
    info.dotnet_type_names = _unique(types, 40)
    if types:
        info.dotnet_assembly_name = types[0].split(".", 1)[0]


def _simple_imphash(dlls: list[str], functions: list[str]) -> str:
    parts = [dll.lower() for dll in sorted(dlls)]
    parts.extend(sorted(function.lower().split("!", 1)[-1] for function in functions))
    return hashlib.md5(",".join(parts).encode("utf-8", errors="ignore")).hexdigest() if parts else ""


def _permission_summary(sections: list[PeSectionInfo]) -> str:
    values = []
    for section in sections:
        flags = ("x" if section.executable else "-") + ("r" if section.readable else "-") + ("w" if section.writable else "-")
        values.append(f"{section.name}:{flags}")
    return ",".join(values[:12])


def _detect_package_type(data: bytes, info: PeInfo) -> str:
    sample = data[: min(len(data), 4 * 1024 * 1024)].lower()
    section_names = {section.name.lower() for section in info.sections}
    if b"pyinstaller" in sample or b"pyi_" in sample:
        return "PyInstaller-like bundle"
    if b"nuitka" in sample:
        return "Nuitka-like bundle"
    if b"cx_freeze" in sample or b"cx-freeze" in sample:
        return "cx_Freeze-like bundle"
    if b"electron" in sample or b"app.asar" in sample:
        return "Electron-like bundle"
    if b"nullsoft" in sample or b"nsis" in sample:
        return "NSIS installer"
    if b"inno setup" in sample:
        return "Inno Setup installer"
    if b"squirrel" in sample:
        return "Squirrel installer"
    if b"autoit" in sample:
        return "AutoIt compiled script"
    if any(name.startswith("upx") for name in section_names):
        return "UPX-like packed structure"
    if b"jvm.dll" in sample or b"javaw.exe" in sample:
        return "Java launcher wrapper"
    return ""


def _cstring(data: bytes, offset: int, limit: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = min(len(data), offset + limit)
    cursor = offset
    while cursor < end and data[cursor] != 0:
        cursor += 1
    return data[offset:cursor].decode("utf-8", errors="replace").strip()


def _unique(values: list[str], limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]
