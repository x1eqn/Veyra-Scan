from __future__ import annotations

from collections import Counter


OPCODES = {
    0x12: "LDC",
    0x13: "LDC",
    0x14: "LDC",
    0x99: "IF",
    0x9A: "IF",
    0x9B: "IF",
    0x9C: "IF",
    0x9D: "IF",
    0x9E: "IF",
    0x9F: "IF",
    0xA0: "IF",
    0xA1: "IF",
    0xA2: "IF",
    0xA3: "IF",
    0xA4: "IF",
    0xA5: "IF",
    0xA6: "IF",
    0xA7: "GOTO",
    0xB2: "GETSTATIC",
    0xB3: "PUTSTATIC",
    0xB4: "GETFIELD",
    0xB5: "PUTFIELD",
    0xB6: "INVOKEVIRTUAL",
    0xB7: "INVOKESPECIAL",
    0xB8: "INVOKESTATIC",
    0xB9: "INVOKEINTERFACE",
    0xC0: "CHECKCAST",
    0xC1: "INSTANCEOF",
}


def opcode_activity_score(data: bytes) -> int:
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return 0
    counts = Counter(OPCODES.get(byte) for byte in data if byte in OPCODES)
    invoke = counts["INVOKEVIRTUAL"] + counts["INVOKESTATIC"] + counts["INVOKEINTERFACE"] + counts["INVOKESPECIAL"]
    fields = counts["GETFIELD"] + counts["PUTFIELD"] + counts["GETSTATIC"] + counts["PUTSTATIC"]
    branches = counts["IF"] + counts["GOTO"]
    score = min(100, invoke * 4 + fields * 2 + branches * 2 + counts["LDC"])
    return score
