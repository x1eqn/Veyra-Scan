from __future__ import annotations

import struct
from dataclasses import dataclass, field


@dataclass
class BytecodeAnalysis:
    parsed: bool
    method_names: list[str] = field(default_factory=list)
    method_refs: list[str] = field(default_factory=list)
    field_refs: list[str] = field(default_factory=list)
    class_refs: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    conditional_branches: int = 0
    backward_branches: int = 0
    methods: list["MethodBytecodeBehavior"] = field(default_factory=list)
    numeric_constants: list[float] = field(default_factory=list)


@dataclass
class MethodBytecodeBehavior:
    name: str
    method_refs: list[str] = field(default_factory=list)
    field_refs: list[str] = field(default_factory=list)
    class_refs: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    conditional_branches: int = 0
    backward_branches: int = 0
    numeric_constants: list[float] = field(default_factory=list)


def analyze_class_bytecode(data: bytes) -> BytecodeAnalysis:
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return BytecodeAnalysis(parsed=False)
    try:
        parser = _ClassParser(data)
        return parser.parse()
    except (IndexError, ValueError, OverflowError):
        return BytecodeAnalysis(parsed=False)


class _ClassParser:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 8
        self.cp: list[object | None] = [None]
        self.analysis = BytecodeAnalysis(parsed=True)

    def parse(self) -> BytecodeAnalysis:
        self._parse_constant_pool()
        self._skip(2)  # access_flags
        this_class = self._read_u2()
        super_class = self._read_u2()
        self._add_unique(self.analysis.class_refs, self._class_name(this_class))
        self._add_unique(self.analysis.class_refs, self._class_name(super_class))
        self._skip_interfaces()
        self._skip_members()
        self._parse_methods()
        return self.analysis

    def _parse_constant_pool(self) -> None:
        count = self._read_u2()
        self.cp = [None] * count
        index = 1
        while index < count:
            tag = self._read_u1()
            if tag == 1:
                length = self._read_u2()
                raw = self._read_bytes(length)
                self.cp[index] = ("Utf8", raw.decode("utf-8", errors="replace"))
            elif tag == 3:
                self.cp[index] = ("Integer", self._read_u4())
            elif tag == 4:
                self.cp[index] = ("Float", self._read_u4())
            elif tag in {5, 6}:
                self.cp[index] = ("LongDouble", self._read_bytes(8))
                index += 1
            elif tag == 7:
                self.cp[index] = ("Class", self._read_u2())
            elif tag == 8:
                self.cp[index] = ("String", self._read_u2())
            elif tag in {9, 10, 11}:
                self.cp[index] = ("Ref", tag, self._read_u2(), self._read_u2())
            elif tag == 12:
                self.cp[index] = ("NameAndType", self._read_u2(), self._read_u2())
            elif tag == 15:
                self.cp[index] = ("MethodHandle", self._read_u1(), self._read_u2())
            elif tag == 16:
                self.cp[index] = ("MethodType", self._read_u2())
            elif tag in {17, 18}:
                self.cp[index] = ("Dynamic", tag, self._read_u2(), self._read_u2())
            elif tag in {19, 20}:
                self.cp[index] = ("ModulePackage", tag, self._read_u2())
            else:
                raise ValueError(f"unknown cp tag: {tag}")
            index += 1

    def _skip_interfaces(self) -> None:
        count = self._read_u2()
        for _ in range(count):
            self._add_unique(self.analysis.class_refs, self._class_name(self._read_u2()))

    def _skip_members(self) -> None:
        count = self._read_u2()
        for _ in range(count):
            self._skip(6)
            self._skip_attributes()

    def _parse_methods(self) -> None:
        count = self._read_u2()
        for _ in range(count):
            self._skip(2)
            method_name = self._utf8(self._read_u2())
            self._skip(2)
            self._add_unique(self.analysis.method_names, method_name)
            attr_count = self._read_u2()
            for _ in range(attr_count):
                attr_name = self._utf8(self._read_u2())
                attr_length = self._read_u4()
                attr_start = self.offset
                if attr_name == "Code":
                    method_ref_start = len(self.analysis.method_refs)
                    field_ref_start = len(self.analysis.field_refs)
                    class_ref_start = len(self.analysis.class_refs)
                    string_start = len(self.analysis.string_literals)
                    branch_start = self.analysis.conditional_branches
                    backward_start = self.analysis.backward_branches
                    numeric_start = len(self.analysis.numeric_constants)
                    self._parse_code_attribute()
                    self.analysis.methods.append(
                        MethodBytecodeBehavior(
                            name=method_name,
                            method_refs=self.analysis.method_refs[method_ref_start:],
                            field_refs=self.analysis.field_refs[field_ref_start:],
                            class_refs=self.analysis.class_refs[class_ref_start:],
                            string_literals=self.analysis.string_literals[string_start:],
                            conditional_branches=self.analysis.conditional_branches - branch_start,
                            backward_branches=self.analysis.backward_branches - backward_start,
                            numeric_constants=self.analysis.numeric_constants[numeric_start:],
                        )
                    )
                self.offset = attr_start + attr_length

    def _parse_code_attribute(self) -> None:
        self._skip(2)  # max_stack
        self._skip(2)  # max_locals
        code_length = self._read_u4()
        code = self._read_bytes(code_length)
        self._scan_code(code)
        exception_count = self._read_u2()
        self._skip(exception_count * 8)
        self._skip_attributes()

    def _skip_attributes(self) -> None:
        count = self._read_u2()
        for _ in range(count):
            self._skip(2)
            self._skip(self._read_u4())

    def _scan_code(self, code: bytes) -> None:
        offset = 0
        while offset < len(code):
            opcode = code[offset]
            if opcode in {0xb2, 0xb3, 0xb4, 0xb5}:  # field refs
                index = _code_u2(code, offset + 1)
                self._add_unique(self.analysis.field_refs, self._ref(index))
                offset += 3
            elif opcode in {0xb6, 0xb7, 0xb8}:  # method refs
                index = _code_u2(code, offset + 1)
                self._add_unique(self.analysis.method_refs, self._ref(index))
                offset += 3
            elif opcode == 0xb9:  # invokeinterface
                index = _code_u2(code, offset + 1)
                self._add_unique(self.analysis.method_refs, self._ref(index))
                offset += 5
            elif opcode == 0xba:  # invokedynamic
                index = _code_u2(code, offset + 1)
                self._add_unique(self.analysis.method_refs, self._dynamic_ref(index))
                offset += 5
            elif opcode in {0xbb, 0xbd, 0xc0, 0xc1}:  # new/anewarray/checkcast/instanceof
                index = _code_u2(code, offset + 1)
                self._add_unique(self.analysis.class_refs, self._class_name(index))
                offset += 3
            elif opcode == 0xc5:  # multianewarray
                index = _code_u2(code, offset + 1)
                self._add_unique(self.analysis.class_refs, self._class_name(index))
                offset += 4
            elif opcode == 0x12:  # ldc
                self._add_ldc(code[offset + 1])
                offset += 2
            elif opcode in {0x13, 0x14}:  # ldc_w / ldc2_w
                self._add_ldc(_code_u2(code, offset + 1))
                offset += 3
            elif opcode == 0xaa:
                offset = _skip_tableswitch(code, offset)
            elif opcode == 0xab:
                offset = _skip_lookupswitch(code, offset)
            elif opcode == 0xc4:
                offset += _wide_length(code, offset)
            elif opcode in set(range(0x99, 0xA7)) | {0xC6, 0xC7}:  # conditional branches
                branch_offset = int.from_bytes(code[offset + 1 : offset + 3], "big", signed=True)
                self.analysis.conditional_branches += 1
                if branch_offset < 0:
                    self.analysis.backward_branches += 1
                offset += 3
            else:
                offset += 1 + OPCODE_OPERANDS.get(opcode, 0)

    def _add_ldc(self, index: int) -> None:
        entry = self._entry(index)
        if not entry:
            return
        if entry[0] == "String":
            self._add_unique(self.analysis.string_literals, self._utf8(entry[1]))
        elif entry[0] == "Class":
            self._add_unique(self.analysis.class_refs, self._class_name(index))
        elif entry[0] == "Integer":
            value = int(entry[1])
            if value >= 2**31:
                value -= 2**32
            self._add_unique(self.analysis.numeric_constants, float(value))
        elif entry[0] == "Float":
            value = struct.unpack(">f", int(entry[1]).to_bytes(4, "big"))[0]
            if value == value and abs(value) != float("inf"):
                self._add_unique(self.analysis.numeric_constants, float(value))

    def _ref(self, index: int) -> str:
        entry = self._entry(index)
        if not entry or entry[0] != "Ref":
            return ""
        _, _tag, class_index, name_type_index = entry
        class_name = self._class_name(class_index)
        name, descriptor = self._name_and_type(name_type_index)
        return f"{class_name}.{name}{descriptor}"

    def _dynamic_ref(self, index: int) -> str:
        entry = self._entry(index)
        if not entry or entry[0] != "Dynamic":
            return ""
        _, _tag, _bootstrap, name_type_index = entry
        name, descriptor = self._name_and_type(name_type_index)
        return f"dynamic.{name}{descriptor}"

    def _name_and_type(self, index: int) -> tuple[str, str]:
        entry = self._entry(index)
        if not entry or entry[0] != "NameAndType":
            return "", ""
        return self._utf8(entry[1]), self._utf8(entry[2])

    def _class_name(self, index: int) -> str:
        entry = self._entry(index)
        if not entry or entry[0] != "Class":
            return ""
        return self._utf8(entry[1])

    def _utf8(self, index: int) -> str:
        entry = self._entry(index)
        if not entry or entry[0] != "Utf8":
            return ""
        return str(entry[1])

    def _entry(self, index: int):
        if index <= 0 or index >= len(self.cp):
            return None
        return self.cp[index]

    def _read_u1(self) -> int:
        value = self.data[self.offset]
        self.offset += 1
        return value

    def _read_u2(self) -> int:
        value = int.from_bytes(self.data[self.offset : self.offset + 2], "big")
        self.offset += 2
        return value

    def _read_u4(self) -> int:
        value = int.from_bytes(self.data[self.offset : self.offset + 4], "big")
        self.offset += 4
        return value

    def _read_bytes(self, length: int) -> bytes:
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def _skip(self, length: int) -> None:
        self.offset += length

    def _add_unique(self, values: list[str], value: str) -> None:
        if value and value not in values:
            values.append(value)


OPCODE_OPERANDS = {
    0x10: 1,
    0x11: 2,
    0x15: 1,
    0x16: 1,
    0x17: 1,
    0x18: 1,
    0x19: 1,
    0x36: 1,
    0x37: 1,
    0x38: 1,
    0x39: 1,
    0x3A: 1,
    0x84: 2,
    0x99: 2,
    0x9A: 2,
    0x9B: 2,
    0x9C: 2,
    0x9D: 2,
    0x9E: 2,
    0x9F: 2,
    0xA0: 2,
    0xA1: 2,
    0xA2: 2,
    0xA3: 2,
    0xA4: 2,
    0xA5: 2,
    0xA6: 2,
    0xA7: 2,
    0xA8: 2,
    0xA9: 1,
    0xC6: 2,
    0xC7: 2,
    0xC8: 4,
    0xC9: 4,
}


def _code_u2(code: bytes, offset: int) -> int:
    return int.from_bytes(code[offset : offset + 2], "big")


def _code_i4(code: bytes, offset: int) -> int:
    return int.from_bytes(code[offset : offset + 4], "big", signed=True)


def _skip_tableswitch(code: bytes, offset: int) -> int:
    cursor = offset + 1
    cursor += (4 - (cursor % 4)) % 4
    cursor += 4
    low = _code_i4(code, cursor)
    cursor += 4
    high = _code_i4(code, cursor)
    cursor += 4
    count = max(0, high - low + 1)
    return min(len(code), cursor + count * 4)


def _skip_lookupswitch(code: bytes, offset: int) -> int:
    cursor = offset + 1
    cursor += (4 - (cursor % 4)) % 4
    cursor += 4
    pairs = max(0, _code_i4(code, cursor))
    cursor += 4
    return min(len(code), cursor + pairs * 8)


def _wide_length(code: bytes, offset: int) -> int:
    if offset + 1 >= len(code):
        return 1
    return 6 if code[offset + 1] == 0x84 else 4
