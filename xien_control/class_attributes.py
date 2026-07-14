from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ClassAttributeSummary:
    parsed: bool = False
    major_version: int = 0
    source_file: str = ""
    inner_classes: set[str] = field(default_factory=set)
    annotations: set[str] = field(default_factory=set)
    local_variables: set[str] = field(default_factory=set)
    signatures: set[str] = field(default_factory=set)
    bootstrap_refs: set[str] = field(default_factory=set)
    descriptors: set[str] = field(default_factory=set)
    numeric_constants: list[float] = field(default_factory=list)
    attribute_count: int = 0


def parse_class_attributes(data: bytes) -> ClassAttributeSummary:
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return ClassAttributeSummary()
    parser = _Parser(data)
    try:
        return parser.parse()
    except (IndexError, ValueError, OverflowError):
        return ClassAttributeSummary()


class _Parser:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 4
        self.summary = ClassAttributeSummary(parsed=True)
        self.cp: list[tuple[str, object] | None] = [None]

    def parse(self) -> ClassAttributeSummary:
        self._read_u2()  # minor
        self.summary.major_version = self._read_u2()
        self._parse_cp()
        self._skip(6)  # access_flags, this_class, super_class
        self._skip_interfaces()
        self._parse_members(fields=True)
        self._parse_members(fields=False)
        self._parse_class_attributes()
        self._collect_global_descriptors()
        return self.summary

    def _parse_cp(self) -> None:
        count = self._read_u2()
        self.cp = [None] * count
        index = 1
        while index < count:
            tag = self._read_u1()
            if tag == 1:
                length = self._read_u2()
                self.cp[index] = ("Utf8", self._read_bytes(length).decode("utf-8", errors="replace"))
            elif tag == 3:
                value = int.from_bytes(self._read_bytes(4), "big", signed=True)
                self.cp[index] = ("Integer", value)
                self.summary.numeric_constants.append(float(value))
            elif tag == 4:
                import struct

                value = struct.unpack(">f", self._read_bytes(4))[0]
                self.cp[index] = ("Float", value)
                self.summary.numeric_constants.append(float(value))
            elif tag == 5:
                value = int.from_bytes(self._read_bytes(8), "big", signed=True)
                self.cp[index] = ("Long", value)
                self.summary.numeric_constants.append(float(value))
                index += 1
            elif tag == 6:
                import struct

                value = struct.unpack(">d", self._read_bytes(8))[0]
                self.cp[index] = ("Double", value)
                self.summary.numeric_constants.append(float(value))
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
                raise ValueError(f"unknown constant pool tag {tag}")
            index += 1

    def _skip_interfaces(self) -> None:
        count = self._read_u2()
        self._skip(count * 2)

    def _parse_members(self, fields: bool) -> None:
        count = self._read_u2()
        for _ in range(count):
            self._skip(2)
            name = self._utf8(self._read_u2())
            descriptor = self._utf8(self._read_u2())
            if descriptor:
                self.summary.descriptors.add(descriptor)
            attr_count = self._read_u2()
            for _ in range(attr_count):
                self._parse_attribute(member_name=name)

    def _parse_class_attributes(self) -> None:
        count = self._read_u2()
        for _ in range(count):
            self._parse_attribute(member_name="")

    def _parse_attribute(self, member_name: str) -> None:
        name = self._utf8(self._read_u2())
        length = self._read_u4()
        start = self.offset
        data = self._read_bytes(length)
        self.summary.attribute_count += 1
        if name == "SourceFile" and len(data) >= 2:
            self.summary.source_file = self._utf8(int.from_bytes(data[:2], "big"))
        elif name == "InnerClasses":
            self._parse_inner_classes(data)
        elif name in {"Signature", "LocalVariableTypeTable"}:
            self._collect_utf8_indexes(data, self.summary.signatures)
        elif name == "Code":
            self._parse_code_attribute(data)
        elif "Annotation" in name or name in {"RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations"}:
            self._collect_utf8_indexes(data, self.summary.annotations)
        elif name == "BootstrapMethods":
            self._collect_utf8_indexes(data, self.summary.bootstrap_refs)
        else:
            if name:
                self._collect_utf8_indexes(data, self.summary.descriptors)
        self.offset = start + length

    def _parse_code_attribute(self, data: bytes) -> None:
        if len(data) < 8:
            return
        cursor = 0
        cursor += 2 + 2
        code_length = int.from_bytes(data[cursor : cursor + 4], "big")
        cursor += 4 + code_length
        if cursor + 2 > len(data):
            return
        exception_count = int.from_bytes(data[cursor : cursor + 2], "big")
        cursor += 2 + exception_count * 8
        if cursor + 2 > len(data):
            return
        attr_count = int.from_bytes(data[cursor : cursor + 2], "big")
        cursor += 2
        for _ in range(attr_count):
            if cursor + 6 > len(data):
                return
            name_index = int.from_bytes(data[cursor : cursor + 2], "big")
            cursor += 2
            attr_name = self._utf8(name_index)
            attr_len = int.from_bytes(data[cursor : cursor + 4], "big")
            cursor += 4
            payload = data[cursor : cursor + attr_len]
            cursor += attr_len
            if attr_name == "LocalVariableTable":
                self._parse_local_variable_table(payload)
            elif attr_name == "LocalVariableTypeTable":
                self._collect_utf8_indexes(payload, self.summary.signatures)
            elif "Annotation" in attr_name:
                self._collect_utf8_indexes(payload, self.summary.annotations)

    def _parse_local_variable_table(self, data: bytes) -> None:
        if len(data) < 2:
            return
        count = int.from_bytes(data[:2], "big")
        cursor = 2
        for _ in range(count):
            if cursor + 10 > len(data):
                return
            cursor += 4
            name_index = int.from_bytes(data[cursor : cursor + 2], "big")
            cursor += 2
            descriptor_index = int.from_bytes(data[cursor : cursor + 2], "big")
            cursor += 2
            cursor += 2
            name = self._utf8(name_index)
            descriptor = self._utf8(descriptor_index)
            if name and not name.startswith("this"):
                self.summary.local_variables.add(name)
            if descriptor:
                self.summary.descriptors.add(descriptor)

    def _parse_inner_classes(self, data: bytes) -> None:
        if len(data) < 2:
            return
        count = int.from_bytes(data[:2], "big")
        cursor = 2
        for _ in range(count):
            if cursor + 8 > len(data):
                return
            inner_index = int.from_bytes(data[cursor : cursor + 2], "big")
            outer_index = int.from_bytes(data[cursor + 2 : cursor + 4], "big")
            inner_name_index = int.from_bytes(data[cursor + 4 : cursor + 6], "big")
            cursor += 8
            for value in (self._class_name(inner_index), self._class_name(outer_index), self._utf8(inner_name_index)):
                if value:
                    self.summary.inner_classes.add(value)

    def _collect_utf8_indexes(self, data: bytes, target: set[str]) -> None:
        for offset in range(0, max(0, len(data) - 1), 2):
            index = int.from_bytes(data[offset : offset + 2], "big")
            value = self._utf8(index)
            if value and any(char.isalpha() for char in value):
                target.add(value)

    def _collect_global_descriptors(self) -> None:
        for entry in self.cp:
            if not entry:
                continue
            if entry[0] == "Utf8":
                value = str(entry[1])
                if value.startswith(("(", "L", "[")) or ";" in value:
                    self.summary.descriptors.add(value)

    def _class_name(self, index: int) -> str:
        entry = self._entry(index)
        if not entry or entry[0] != "Class":
            return ""
        return self._utf8(int(entry[1]))

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
