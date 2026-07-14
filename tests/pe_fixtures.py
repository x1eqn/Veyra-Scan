from __future__ import annotations


def minimal_pe_bytes(section_data: bytes | None = None, section_name: bytes = b".text") -> bytes:
    section_data = section_data if section_data is not None else b"\x90" * 512
    raw_pointer = 0x200
    raw_size = max(0x200, ((len(section_data) + 0x1FF) // 0x200) * 0x200)
    section_data = section_data.ljust(raw_size, b"\x00")
    dos = bytearray(b"MZ" + b"\x00" * 0x3A)
    dos += (0x80).to_bytes(4, "little")
    data = dos.ljust(0x80, b"\x00")
    coff = bytearray()
    coff += b"PE\x00\x00"
    coff += (0x8664).to_bytes(2, "little")
    coff += (1).to_bytes(2, "little")
    coff += (1_700_000_000).to_bytes(4, "little")
    coff += (0).to_bytes(4, "little")
    coff += (0).to_bytes(4, "little")
    coff += (0xF0).to_bytes(2, "little")
    coff += (0x2022).to_bytes(2, "little")
    optional = bytearray(0xF0)
    optional[0:2] = (0x20B).to_bytes(2, "little")
    optional[16:20] = (0x1000).to_bytes(4, "little")
    optional[24:32] = (0x140000000).to_bytes(8, "little")
    optional[88:90] = (3).to_bytes(2, "little")
    section = bytearray(40)
    section[0:8] = section_name[:8].ljust(8, b"\x00")
    section[8:12] = len(section_data).to_bytes(4, "little")
    section[12:16] = (0x1000).to_bytes(4, "little")
    section[16:20] = raw_size.to_bytes(4, "little")
    section[20:24] = raw_pointer.to_bytes(4, "little")
    section[36:40] = (0x60000020).to_bytes(4, "little")
    data += coff + optional + section
    data = data.ljust(raw_pointer, b"\x00")
    data += section_data
    return bytes(data)


def high_entropy_bytes(size: int = 4096) -> bytes:
    return bytes((index * 37 + 11) % 256 for index in range(size))
