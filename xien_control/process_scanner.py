from __future__ import annotations

import concurrent.futures
import ctypes
import datetime as dt
import hashlib
import math
import os
import re
import sys
import time
import zipfile
from bisect import bisect_right
from collections import Counter
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote

from .client_names import find_client_name_matches


if os.name == "nt":
    from ctypes import wintypes


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
EXECUTABLE_PROTECTIONS = {0x10, 0x20, 0x40, 0x80}
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
THREAD_QUERY_INFORMATION = 0x0040
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


@dataclass(frozen=True)
class MemorySignature:
    signature_id: str
    label: str
    pattern: str | bytes
    severity: str = "high"
    encoding: str = "ascii"
    hex_pattern: bool = False
    raw_regex: bool = False

    def compile(self) -> re.Pattern[bytes]:
        if self.raw_regex:
            raw_expression = self.pattern if isinstance(self.pattern, bytes) else str(self.pattern).encode("ascii")
            return re.compile(raw_expression, re.IGNORECASE)
        if self.hex_pattern:
            parts = str(self.pattern).split()
            expression = b"".join(b"." if part == "??" else re.escape(bytes([int(part, 16)])) for part in parts)
            return re.compile(expression, re.DOTALL)
        raw = self.pattern if isinstance(self.pattern, bytes) else str(self.pattern).encode(self.encoding)
        return re.compile(re.escape(raw), re.IGNORECASE)


@dataclass
class ProcessFinding:
    pid: int
    process_name: str
    detector: str
    finding_type: str
    severity: str
    indicator: str
    address: str = ""
    path: str = ""
    explanation: str = ""
    confidence: str = "medium"
    evidence_score: int = 0
    memory_type: str = ""
    protection: str = ""
    region_base: str = ""


@dataclass
class JavaProcessScanResult:
    pid: int
    process_name: str = "javaw.exe"
    executable: str = ""
    parent_process_name: str = ""
    process_started_at: str = ""
    thread_count: int = 0
    working_set_bytes: int = 0
    private_memory_bytes: int = 0
    admin: bool = False
    scanned_bytes: int = 0
    scanned_regions: int = 0
    elapsed_seconds: float = 0.0
    modules_seen: int = 0
    module_integrity_checked: int = 0
    module_disk_mismatches: int = 0
    open_files_seen: int = 0
    jvm_arguments_seen: int = 0
    jar_artifacts_seen: int = 0
    runtime_jars: list[str] = field(default_factory=list)
    memory_jar_paths: list[str] = field(default_factory=list)
    disk_mod_jars: list[str] = field(default_factory=list)
    runtime_only_jars: list[str] = field(default_factory=list)
    runtime_jar_details: list[dict[str, object]] = field(default_factory=list)
    runtime_jars_probed: int = 0
    runtime_class_origins: list[dict[str, object]] = field(default_factory=list)
    attributed_classes_seen: int = 0
    memory_class_hints_seen: int = 0
    memory_scan_stop_reason: str = ""
    readable_bytes_seen: int = 0
    successful_regions: int = 0
    memory_read_attempts: int = 0
    memory_read_failures: int = 0
    memory_partial_reads: int = 0
    memory_planned_chunks: int = 0
    memory_completed_chunks: int = 0
    memory_sampling_mode: str = ""
    memory_read_success_percent: float = 0.0
    memory_coverage_quality: str = "Unavailable"
    private_executable_regions: int = 0
    private_executable_bytes: int = 0
    hidden_pe_regions: list[str] = field(default_factory=list)
    unlisted_image_regions: list[str] = field(default_factory=list)
    private_exec_thread_starts: list[dict[str, object]] = field(default_factory=list)
    findings: list[ProcessFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["review"] = any(
            item.evidence_score >= 70
            or (item.severity in {"high", "critical"} and item.confidence != "low")
            for item in self.findings
        )
        return payload


class BaseProcessDetector:
    name = "base"

    def signatures(self) -> tuple[MemorySignature, ...]:
        return ()

    def analyze_artifacts(self, pid: int, process_name: str, modules: list[str], open_files: list[str]) -> list[ProcessFinding]:
        return []


class DoomsdayDetector(BaseProcessDetector):
    name = "DoomsdayDetector"

    def signatures(self) -> tuple[MemorySignature, ...]:
        return (
            MemorySignature("DOOMSDAY_NAME", "Doomsday client name", "doomsday", "critical"),
            MemorySignature("DOOMSDAY_CLASS", "Doomsday Java class", "DoomsdayClient", "critical"),
            MemorySignature("DOOMSDAY_PATH", "Doomsday package/config path", "doomsday/config", "high"),
            MemorySignature("DOOMSDAY_UTF16", "Doomsday UTF-16 residue", "doomsday", "high", encoding="utf-16le"),
            MemorySignature("DOOMSDAY_BYTES", "Doomsday ASCII byte signature", "64 6f 6f 6d 73 64 61 79", "critical", hex_pattern=True),
        )

    def analyze_artifacts(self, pid: int, process_name: str, modules: list[str], open_files: list[str]) -> list[ProcessFinding]:
        findings: list[ProcessFinding] = []
        for path in [*modules, *open_files]:
            if "doomsday" in path.lower():
                findings.append(ProcessFinding(pid, process_name, self.name, "file_or_module", "critical", "doomsday", path=path, explanation="A loaded/open artifact contains the Doomsday identifier."))
        return findings


class GenericModDetector(BaseProcessDetector):
    name = "GenericModDetector"
    STRONG_NAMES = {
        "aimassist", "autoclicker", "ghostclient", "killaura", "triggerbot",
    }
    TEMP_NATIVE_DLL_NAMES = {"player.dll", "glfw.dll", "openal.dll", "jemalloc.dll", "lwjgl.dll"}

    def signatures(self) -> tuple[MemorySignature, ...]:
        behavior_names = {"aimassist", "autoclicker", "ghostclient", "killaura", "triggerbot"}
        return tuple(
            MemorySignature(
                f"GENERIC_{name.upper()}",
                f"Suspicious client/mod identifier: {name}",
                name,
                "medium" if name in behavior_names else "low",
            )
            for name in sorted(self.STRONG_NAMES)
        )

    def analyze_artifacts(self, pid: int, process_name: str, modules: list[str], open_files: list[str]) -> list[ProcessFinding]:
        findings: list[ProcessFinding] = []
        for path in _unique([*modules, *open_files]):
            lower = path.lower()
            identity_matches = find_client_name_matches([Path(path).name, path])
            if identity_matches:
                identity = identity_matches[0]
                findings.append(ProcessFinding(pid, process_name, self.name, "known_client_artifact", "high", identity.family, path=path, explanation=f"A loaded/open runtime artifact matches a known client family ({identity.kind}, {identity.similarity:.0%})."))
                continue
            matched = next((name for name in self.STRONG_NAMES if name in lower), "")
            if matched:
                findings.append(ProcessFinding(pid, process_name, self.name, "suspicious_artifact", "high", matched, path=path, explanation="A loaded module/open file path contains a strong client/mod identifier."))
                continue
            normalized_path = lower.replace("/", "\\")
            file_name = normalized_path.rsplit("\\", 1)[-1]
            launcher_native = (
                file_name in self.TEMP_NATIVE_DLL_NAMES
                and "\\native\\" in normalized_path
            ) or bool(re.fullmatch(r"lib\d+\.dll", file_name))
            expected_native = launcher_native or any(marker in lower for marker in ("\\natives\\", "lwjgl", "glfw", "openal", "jemalloc", "jvm.dll", "java.dll"))
            if lower.endswith(".dll") and not expected_native and any(marker in lower for marker in ("\\temp\\", "\\appdata\\local\\temp\\")):
                findings.append(ProcessFinding(pid, process_name, self.name, "unusual_loaded_dll", "medium", "user-temp DLL", path=path, explanation="A DLL associated with javaw.exe is loaded/open from a temporary user-writable directory."))
        return findings


class RestrictedModDetector(BaseProcessDetector):
    """Detect client-side helpers commonly restricted by multiplayer rules.

    These are review signals, not proof of cheating: a server may allow a
    feature, and a path/string can be a library or documentation reference.
    Artifact matches are therefore kept separate from the stronger known
    client detector and are explained in the report.
    """

    name = "RestrictedModDetector"
    FEATURES = (
        ("FREECAM", "Freecam", rb"free[ _./\\-]*cam", "high"),
        ("FREELOOK", "FreeLook", rb"free[ _./\\-]*look", "high"),
        ("XRAY", "Xray", rb"x[ _./\\-]*ray|wall[ _./\\-]*hack", "high"),
        ("AUTOTOTEM", "Auto-Totem", rb"auto[ _./\\-]*totem|totem[ _./\\-]*(?:pop|switch|swap)", "high"),
        ("MACESWAP", "Mace/Swap helper", rb"mace[ _./\\-]*(?:swap|switch)|swap[ _./\\-]*(?:helper|mace)", "high"),
        ("REACHHELPER", "Reach helper", rb"reach[ _./\\-]*helper", "high"),
        ("MOUSE_TWEAKS", "MouseTweaks", rb"mouse[ _./\\-]*tweaks|yalter[./\\\\]+mousetweaks", "low"),
    )

    def signatures(self) -> tuple[MemorySignature, ...]:
        signatures: list[MemorySignature] = []
        for feature_id, label, expression, severity in self.FEATURES:
            # A bare Mace/Swap phrase in JVM memory is not specific enough to
            # distinguish a server guide, UI text, or another mod. Keep the
            # reliable artifact finder below, but require a file/config or a
            # second runtime signal before reporting this feature from memory.
            if feature_id == "MACESWAP":
                continue
            signatures.append(MemorySignature(f"RESTRICTED_{feature_id}_ASCII", f"{label} identifier in JVM memory", expression, severity, raw_regex=True))
            # A number of Java string constants are stored as UTF-16LE in
            # native/JVM buffers. Keep a direct variant for those regions too.
            text = label.lower().replace("/", "")
            utf16 = b"(?:" + re.escape(text.encode("utf-16le")) + b")"
            signatures.append(MemorySignature(f"RESTRICTED_{feature_id}_UTF16", f"{label} UTF-16 identifier in JVM memory", utf16, severity, raw_regex=True))
        return tuple(signatures)

    def analyze_artifacts(self, pid: int, process_name: str, modules: list[str], open_files: list[str]) -> list[ProcessFinding]:
        findings: list[ProcessFinding] = []
        for path in _unique([*modules, *open_files]):
            lower = path.lower()
            normalized = re.sub(r"[^a-z0-9]+", "", lower)
            for feature_id, label, _expression, severity in self.FEATURES:
                aliases = {
                    "FREECAM": ("freecam",),
                    "FREELOOK": ("freelook",),
                    "XRAY": ("xray", "wallhack"),
                    "AUTOTOTEM": ("autototem", "totempop", "totemswap"),
                    "MACESWAP": ("maceswap", "swaphelper", "autobreachswap"),
                    "REACHHELPER": ("reachhelper",),
                    "MOUSE_TWEAKS": ("mousetweaks", "yaltermousetweaks"),
                }[feature_id]
                if any(alias in normalized for alias in aliases):
                    findings.append(ProcessFinding(
                        pid, process_name, self.name, "restricted_mod_artifact", severity, label,
                        path=path,
                        explanation=f"A loaded/open artifact contains a {label} identifier. This is a server-rule review signal and is not by itself proof of cheating.",
                    ))
        return findings


class KnownClientMemoryDetector(BaseProcessDetector):
    name = "KnownClientMemoryDetector"
    MEMORY_NAMES = (
        "liquidbounce", "meteorclient", "wurstclient", "vapeclient", "vapelite", "ravenbplus",
        "prestigeclient", "phantomclient", "slinkyclient", "whiteoutclient", "entropyclient",
        "fdpclient", "tenacity", "novoline", "zeroday", "bleachhack", "rusherhack",
        "thunderhack", "grimclient", "doomsdayclient", "3arthh4ck",
    )

    def signatures(self) -> tuple[MemorySignature, ...]:
        ascii_expression = b"(?:" + b"|".join(re.escape(name.encode("ascii")) for name in self.MEMORY_NAMES) + b")"
        utf16_expression = b"(?:" + b"|".join(re.escape(name.encode("utf-16le")) for name in self.MEMORY_NAMES) + b")"
        return (
            MemorySignature("KNOWN_CLIENT_FAMILY_ASCII", "Known client identity in JVM memory", ascii_expression, "high", raw_regex=True),
            MemorySignature("KNOWN_CLIENT_FAMILY_UTF16", "Known client UTF-16 identity in JVM memory", utf16_expression, "high", raw_regex=True),
        )


class JvmInjectionDetector(BaseProcessDetector):
    name = "JvmInjectionDetector"

    def analyze_artifacts(self, pid: int, process_name: str, modules: list[str], open_files: list[str]) -> list[ProcessFinding]:
        findings: list[ProcessFinding] = []
        for value in open_files:
            lower = value.lower()
            if lower.startswith(("-javaagent:", "-agentpath:")):
                agent_path = value.split(":", 1)[1]
                identity = find_client_name_matches([agent_path])
                severity = "high" if identity else "medium"
                indicator = identity[0].family if identity else value.split(":", 1)[0]
                findings.append(ProcessFinding(pid, process_name, self.name, "jvm_agent", severity, indicator, path=agent_path, explanation="The running JVM was started with an external Java/native agent. Known client identity raises severity; otherwise verify the launcher or profiler context."))
            elif lower.startswith("-agentlib:"):
                findings.append(ProcessFinding(pid, process_name, self.name, "jvm_agent_library", "medium", value, explanation="The running JVM uses an agent library. This can be legitimate debugging/profiling software and requires context."))
            elif lower in {"-noverify", "-xverify:none"}:
                findings.append(ProcessFinding(pid, process_name, self.name, "verification_disabled", "low", value, explanation="JVM bytecode verification was disabled. Some launchers use this legitimately."))
            elif lower.startswith("-xbootclasspath"):
                findings.append(ProcessFinding(pid, process_name, self.name, "boot_classpath_override", "medium", value, explanation="The JVM boot class path was extended or replaced. This can be legitimate, but it changes classes loaded before normal game mods."))
            elif lower.startswith("-djava.system.class.loader="):
                findings.append(ProcessFinding(pid, process_name, self.name, "custom_system_class_loader", "medium", value, explanation="A custom JVM system class loader is active. Verify the launcher or profiling tool that supplied it."))
            elif lower.startswith(("java_tool_options=", "jdk_java_options=", "_java_options=")) and any(marker in lower for marker in ("-javaagent:", "-agentpath:", "-agentlib:", "-xbootclasspath")):
                findings.append(ProcessFinding(pid, process_name, self.name, "environment_jvm_injection", "high", value.split("=", 1)[0], path=value, explanation="A JVM injection or boot-classpath option was supplied through a Java environment variable rather than the visible command line."))
        return findings


class _MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD if os.name == "nt" else ctypes.c_ulong),
        ("PartitionId", ctypes.c_ushort),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD if os.name == "nt" else ctypes.c_ulong),
        ("Protect", wintypes.DWORD if os.name == "nt" else ctypes.c_ulong),
        ("Type", wintypes.DWORD if os.name == "nt" else ctypes.c_ulong),
    ]


@dataclass(frozen=True)
class _ReadableRegion:
    base: int
    size: int
    memory_type: int = 0
    allocation_base: int = 0
    protection: int = 0


@dataclass(frozen=True)
class _MemoryReadTask:
    address: int
    size: int
    region_base: int


def _evenly_spaced_indices(count: int, limit: int) -> list[int]:
    if count <= 0 or limit <= 0:
        return []
    if limit >= count:
        return list(range(count))
    if limit == 1:
        return [count // 2]
    return sorted({round(index * (count - 1) / (limit - 1)) for index in range(limit)})


def _spread_read_order(values: list[int]) -> list[int]:
    """Order samples so an early timeout still covers the full address range."""
    remaining = sorted(set(values))
    if len(remaining) <= 2:
        return remaining
    ordered = [remaining.pop(0), remaining.pop(-1)]
    while remaining:
        chosen = max(remaining, key=lambda value: min(abs(value - used) for used in ordered))
        ordered.append(chosen)
        remaining.remove(chosen)
    return ordered


def _build_memory_scan_plan(regions: list[_ReadableRegion], chunk_size: int, max_bytes: int) -> tuple[list[_MemoryReadTask], str]:
    """Build a full or address-balanced scan plan without low-address bias."""
    if not regions or max_bytes <= 0:
        return [], "full"
    chunk_size = max(64 * 1024, chunk_size)
    chunk_counts = [(region.size + chunk_size - 1) // chunk_size for region in regions]
    starts: list[int] = []
    total_chunks = 0
    for count in chunk_counts:
        starts.append(total_chunks)
        total_chunks += count
    max_chunks = max(1, max_bytes // chunk_size)
    if total_chunks <= max_chunks:
        selected = list(range(total_chunks))
        mode = "full"
    else:
        selected_set: set[int] = set()
        # Always prioritize allocation heads that contain executable private
        # memory. JIT code caches are common, but a valid PE at such a head is
        # a useful manual-map signal and must not be skipped by sampling.
        private_exec_allocations = {
            region.allocation_base or region.base
            for region in regions
            if region.memory_type == MEM_PRIVATE and (region.protection & 0xFF) in EXECUTABLE_PROTECTIONS
        }
        native_head_indices = [
            index for index, region in enumerate(regions)
            if region.base == (region.allocation_base or region.base) and (region.allocation_base or region.base) in private_exec_allocations
        ]
        native_budget = min(len(native_head_indices), max(1, max_chunks // 8))
        for selected_index in _evenly_spaced_indices(len(native_head_indices), native_budget):
            selected_set.add(starts[native_head_indices[selected_index]])
        edge_budget = max(1, max_chunks // 5)
        for region_index in _evenly_spaced_indices(len(regions), min(len(regions), edge_budget)):
            selected_set.add(starts[region_index])
        for region_index in _evenly_spaced_indices(len(regions), min(len(regions), edge_budget)):
            selected_set.add(starts[region_index] + chunk_counts[region_index] - 1)
        remaining = max(0, max_chunks - len(selected_set))
        even_candidates = [
            index for index in _evenly_spaced_indices(total_chunks, min(total_chunks, max_chunks * 3))
            if index not in selected_set
        ]
        for candidate_index in _evenly_spaced_indices(len(even_candidates), remaining):
            selected_set.add(even_candidates[candidate_index])
        # Rounding and edge overlap can leave a few slots. Fill them with a
        # deterministic stride across the entire address space.
        if len(selected_set) < max_chunks:
            stride = max(1, total_chunks // max_chunks)
            cursor = stride // 2
            while cursor < total_chunks and len(selected_set) < max_chunks:
                selected_set.add(cursor)
                cursor += stride
        selected = _spread_read_order(sorted(selected_set)[:max_chunks])
        mode = "balanced"

    tasks: list[_MemoryReadTask] = []
    for global_index in selected:
        region_index = bisect_right(starts, global_index) - 1
        region = regions[region_index]
        local_index = global_index - starts[region_index]
        offset = local_index * chunk_size
        tasks.append(_MemoryReadTask(region.base + offset, min(chunk_size, region.size - offset), region.base))
    return tasks, mode


class ProcessMemoryReader:
    def __init__(self, pid: int, chunk_size: int = 4 * 1024 * 1024, max_bytes: int = 1024 * 1024 * 1024, time_budget: float = 20.0):
        self.pid = pid
        self.chunk_size = max(64 * 1024, chunk_size)
        self.max_bytes = max_bytes
        self.time_budget = time_budget
        self.handle = None
        self.scanned_bytes = 0
        self.scanned_regions = 0
        self.stop_reason = "not_started"
        self.readable_bytes_seen = 0
        self.successful_regions = 0
        self.read_attempts = 0
        self.failed_reads = 0
        self.partial_reads = 0
        self.planned_chunks = 0
        self.completed_chunks = 0
        self.sampling_mode = ""
        self.regions: list[_ReadableRegion] = []
        self.private_executable_regions: list[_ReadableRegion] = []
        self.image_allocation_bases: set[int] = set()
        self.region_by_base: dict[int, _ReadableRegion] = {}
        self.region_starts: list[int] = []

    def __enter__(self):
        if os.name != "nt":
            raise OSError("Process memory scanning is available only on Windows.")
        kernel32 = _kernel32()
        self.handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return self

    def __exit__(self, *_args):
        if self.handle:
            _kernel32().CloseHandle(self.handle)
            self.handle = None

    def region_for_address(self, address: int) -> _ReadableRegion | None:
        if not self.region_starts:
            return None
        index = bisect_right(self.region_starts, address) - 1
        if index < 0:
            return None
        region = self.regions[index]
        return region if region.base <= address < region.base + region.size else None

    def chunks(self) -> Iterable[tuple[int, bytes]]:
        kernel32 = _kernel32()
        address = 0
        deadline = time.monotonic() + self.time_budget
        discovery_deadline = min(deadline, time.monotonic() + min(5.0, max(1.0, self.time_budget * 0.25)))
        max_address = 0x7FFFFFFFFFFF if sys.maxsize > 2**32 else 0x7FFFFFFF
        info = _MemoryBasicInformation()
        regions: list[_ReadableRegion] = []
        committed_regions: list[_ReadableRegion] = []
        map_complete = False
        while address < max_address and time.monotonic() < discovery_deadline:
            queried = kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info))
            if not queried:
                map_complete = True
                break
            base = int(info.BaseAddress or address)
            size = int(info.RegionSize)
            next_address = base + max(size, 0x1000)
            protection = int(info.Protect)
            allocation_base = int(info.AllocationBase or base)
            if int(info.State) == MEM_COMMIT and size > 0:
                committed_regions.append(_ReadableRegion(base, size, int(info.Type), allocation_base, protection))
            readable = int(info.State) == MEM_COMMIT and not (protection & PAGE_GUARD) and not (protection & PAGE_NOACCESS) and (protection & 0xFF) in READABLE_PROTECTIONS
            if readable and size > 0:
                regions.append(_ReadableRegion(base, size, int(info.Type), allocation_base, protection))
            address = next_address
        if address >= max_address:
            map_complete = True
        self.regions = regions
        self.region_by_base = {region.base: region for region in regions}
        self.region_starts = [region.base for region in regions]
        self.private_executable_regions = [
            region for region in committed_regions
            if region.memory_type == MEM_PRIVATE and (region.protection & 0xFF) in EXECUTABLE_PROTECTIONS
        ]
        self.image_allocation_bases = {
            region.allocation_base or region.base for region in committed_regions if region.memory_type == MEM_IMAGE
        }
        self.scanned_regions = len(regions)
        self.readable_bytes_seen = sum(region.size for region in regions)
        tasks, self.sampling_mode = _build_memory_scan_plan(regions, self.chunk_size, self.max_bytes)
        self.planned_chunks = len(tasks)
        successful_region_bases: set[int] = set()
        for task in tasks:
            if time.monotonic() >= deadline:
                break
            request_size = min(task.size, max(0, self.max_bytes - self.scanned_bytes))
            if request_size <= 0:
                break
            buffer = ctypes.create_string_buffer(request_size)
            read = ctypes.c_size_t()
            self.read_attempts += 1
            ok = kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(task.address), buffer, request_size, ctypes.byref(read))
            if read.value:
                data = buffer.raw[: read.value]
                self.scanned_bytes += len(data)
                self.completed_chunks += 1
                successful_region_bases.add(task.region_base)
                if not ok or read.value < request_size:
                    self.partial_reads += 1
                yield task.address, data
            else:
                self.failed_reads += 1
        self.successful_regions = len(successful_region_bases)
        if time.monotonic() >= deadline and self.completed_chunks < self.planned_chunks:
            self.stop_reason = "time budget reached"
        elif not map_complete:
            self.stop_reason = "memory map discovery timed out"
        elif self.sampling_mode == "balanced":
            self.stop_reason = "balanced sample completed"
        elif self.completed_chunks >= self.planned_chunks:
            self.stop_reason = "memory map completed"
        else:
            self.stop_reason = "byte limit reached"


class JavaProcessScannerEngine:
    def __init__(self, detectors: list[BaseProcessDetector] | None = None, max_workers: int = 2):
        self.detectors = detectors or [DoomsdayDetector(), KnownClientMemoryDetector(), GenericModDetector(), RestrictedModDetector(), JvmInjectionDetector()]
        self.max_workers = max(1, min(max_workers, 4))

    @staticmethod
    def is_administrator() -> bool:
        if os.name != "nt":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    def scan(self, installed_mod_paths: Iterable[Path] | None = None) -> list[JavaProcessScanResult]:
        processes = _javaw_processes()
        if not processes:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(processes)), thread_name_prefix="veyra-javaw") as pool:
            results = list(pool.map(lambda item: self._scan_process(*item), processes))
        installed = [Path(path) for path in (installed_mod_paths or [])]
        for result in results:
            _compare_runtime_to_disk(result, installed)
            result.findings = _calibrate_process_findings(_dedupe_findings(result.findings))[:150]
        return results

    def _scan_process(self, pid: int, executable: str) -> JavaProcessScanResult:
        started = time.monotonic()
        result = JavaProcessScanResult(pid=pid, executable=executable, admin=self.is_administrator())
        metadata = _process_metadata(pid)
        result.parent_process_name = str(metadata.get("parent_process_name", ""))
        result.process_started_at = str(metadata.get("process_started_at", ""))
        result.thread_count = int(metadata.get("thread_count", 0) or 0)
        result.working_set_bytes = int(metadata.get("working_set_bytes", 0) or 0)
        result.private_memory_bytes = int(metadata.get("private_memory_bytes", 0) or 0)
        if not result.admin:
            result.notes.append("Veyra Scan is not elevated; some javaw.exe memory regions or handles may be inaccessible.")
        module_records = _loaded_module_records(pid)
        modules = [str(record.get("path", "")) for record in module_records if record.get("path")]
        module_bases = {int(record.get("base", 0) or 0) for record in module_records if record.get("base")}
        thread_starts, thread_notes = _thread_start_addresses(pid)
        open_files, file_notes = _open_files(pid)
        jvm_artifacts, argument_count, command_notes = _jvm_runtime_artifacts(pid)
        result.notes.extend(file_notes)
        result.notes.extend(command_notes)
        result.notes.extend(thread_notes)
        result.modules_seen = len(modules)
        module_findings, checked_modules, mismatched_modules = _loaded_module_integrity_findings(
            module_records, pid, result.process_name,
        )
        result.findings.extend(module_findings)
        result.module_integrity_checked = checked_modules
        result.module_disk_mismatches = mismatched_modules
        result.open_files_seen = len(open_files)
        result.jvm_arguments_seen = argument_count
        result.jvm_arguments_seen = argument_count
        artifacts = _unique([*open_files, *jvm_artifacts])
        result.runtime_jars = _jar_artifact_paths(artifacts)
        result.jar_artifacts_seen = len(result.runtime_jars)
        for detector in self.detectors:
            result.findings.extend(detector.analyze_artifacts(pid, result.process_name, modules, artifacts))

        compiled = [(detector, signature, signature.compile()) for detector in self.detectors for signature in detector.signatures()]
        seen: set[tuple[str, str]] = set()
        max_pattern = max((len(str(signature.pattern)) for _detector, signature, _regex in compiled), default=64)
        tail = b""
        previous_end: int | None = None
        memory_jars: set[str] = set()
        memory_class_hints: set[tuple[str, str]] = set()
        class_origins: dict[tuple[str, str], dict[str, object]] = {}
        hidden_pe_allocations: set[int] = set()
        private_exec_regions: list[_ReadableRegion] = []
        image_allocation_bases: set[int] = set()
        try:
            with ProcessMemoryReader(pid) as reader:
                for base, chunk in reader.chunks():
                    if previous_end is None or base != previous_end:
                        tail = b""
                    window = tail + chunk
                    window_base = base - len(tail)
                    if len(memory_jars) < 200:
                        memory_jars.update(_extract_memory_jar_paths(window, limit=200 - len(memory_jars)))
                    if len(class_origins) < 300:
                        for origin in _extract_memory_class_origins(window, window_base, limit=300 - len(class_origins)):
                            origin_key = (_normalized_windows_path(str(origin.get("jar_path", ""))), str(origin.get("class_entry", "")).lower())
                            class_origins.setdefault(origin_key, origin)
                            memory_jars.add(str(origin.get("jar_path", "")))
                    region = reader.region_for_address(base)
                    if region and base == (region.allocation_base or region.base) and _looks_like_pe_image(chunk):
                        private_allocations = {item.allocation_base or item.base for item in reader.private_executable_regions}
                        if (region.allocation_base or region.base) in private_allocations:
                            hidden_pe_allocations.add(region.allocation_base or region.base)
                    if len(memory_class_hints) < 40:
                        for class_path, family, offset in _extract_suspicious_class_hints(window, limit=40 - len(memory_class_hints)):
                            key = (class_path.lower(), family)
                            if key in memory_class_hints:
                                continue
                            memory_class_hints.add(key)
                            hint_address = window_base + offset
                            hint_region = reader.region_for_address(hint_address)
                            result.findings.append(ProcessFinding(
                                pid,
                                result.process_name,
                                "MemoryClassHintDetector",
                                "memory_class_hint",
                                "high" if family in {"known-client", "triggerbot", "killaura", "autoclicker"} else "medium",
                                f"{family} class-path hint",
                                address=hex(hint_address),
                                path=class_path,
                                explanation="A class-shaped JVM memory value contains a restricted feature or known-client family. This is stronger than a bare word, but is correlated with runtime artifacts before being treated as high confidence.",
                                confidence="medium",
                                memory_type=_memory_type_label(hint_region.memory_type) if hint_region else "",
                                protection=_protection_label(hint_region.protection) if hint_region else "",
                                region_base=hex(hint_region.base) if hint_region else "",
                            ))
                    for detector, signature, regex in compiled:
                        key = (detector.name, signature.signature_id)
                        if key in seen:
                            continue
                        match = regex.search(window)
                        if match:
                            seen.add(key)
                            indicator = signature.label
                            if detector.name == "KnownClientMemoryDetector":
                                matched_name = match.group().replace(b"\x00", b"").decode("ascii", errors="replace")
                                indicator = f"{signature.label}: {matched_name}"
                            match_address = window_base + match.start()
                            match_region = reader.region_for_address(match_address)
                            result.findings.append(ProcessFinding(
                                pid,
                                result.process_name,
                                detector.name,
                                "memory_signature",
                                signature.severity,
                                indicator,
                                address=hex(match_address),
                                explanation="A configured signature matched a readable committed memory region. Raw surrounding memory is not retained.",
                                memory_type=_memory_type_label(match_region.memory_type) if match_region else "",
                                protection=_protection_label(match_region.protection) if match_region else "",
                                region_base=hex(match_region.base) if match_region else "",
                            ))
                    tail = window[-max(32, max_pattern) :]
                    previous_end = base + len(chunk)
                result.scanned_bytes = reader.scanned_bytes
                result.scanned_regions = reader.scanned_regions
                result.memory_scan_stop_reason = reader.stop_reason
                result.readable_bytes_seen = reader.readable_bytes_seen
                result.successful_regions = reader.successful_regions
                result.memory_read_attempts = reader.read_attempts
                result.memory_read_failures = reader.failed_reads
                result.memory_partial_reads = reader.partial_reads
                result.memory_planned_chunks = reader.planned_chunks
                result.memory_completed_chunks = reader.completed_chunks
                result.memory_sampling_mode = reader.sampling_mode
                private_exec_regions = list(reader.private_executable_regions)
                image_allocation_bases = set(reader.image_allocation_bases)
                successful_reads = max(0, reader.read_attempts - reader.failed_reads)
                result.memory_read_success_percent = round((successful_reads / reader.read_attempts) * 100, 1) if reader.read_attempts else 0.0
        except (OSError, PermissionError) as exc:
            result.notes.append(f"Memory scan unavailable: {exc}")
            result.memory_scan_stop_reason = "unavailable"
        verified_origins = _verify_class_origins(list(class_origins.values()))
        result.runtime_class_origins = verified_origins[:300]
        result.attributed_classes_seen = len(result.runtime_class_origins)
        result.findings.extend(_class_origin_findings(result.runtime_class_origins, pid, result.process_name))
        result.memory_jar_paths = sorted((path for path in memory_jars if path), key=str.lower)[:300]
        result.memory_class_hints_seen = len(memory_class_hints)
        result.private_executable_regions = len(private_exec_regions)
        result.private_executable_bytes = sum(region.size for region in private_exec_regions)
        unlisted_image_allocations = {base for base in image_allocation_bases if base and base not in module_bases} if module_bases else set()
        if image_allocation_bases and not module_bases:
            result.notes.append("Native image cross-check was skipped because the Toolhelp module snapshot was unavailable.")
        native_findings, private_thread_matches = _native_memory_findings(
            pid,
            result.process_name,
            private_exec_regions,
            hidden_pe_allocations,
            unlisted_image_allocations,
            thread_starts,
        )
        result.findings.extend(native_findings)
        result.hidden_pe_regions = [hex(base) for base in sorted(hidden_pe_allocations)]
        result.unlisted_image_regions = [hex(base) for base in sorted(unlisted_image_allocations)[:100]]
        result.private_exec_thread_starts = [
            {**item, "start_address_hex": hex(int(item["start_address"])), "allocation_base_hex": hex(int(item["allocation_base"]))}
            for item in private_thread_matches
        ]
        result.runtime_jars = _unique([*result.runtime_jars, *result.memory_jar_paths])[:300]
        result.jar_artifacts_seen = len(result.runtime_jars)
        result.runtime_jar_details = _runtime_jar_details(result.runtime_jars, result.memory_jar_paths, artifacts)
        runtime_probe_findings, result.runtime_jars_probed = _runtime_jar_probe_findings(
            result.runtime_jar_details, pid, result.process_name,
        )
        result.findings.extend(runtime_probe_findings)
        result.findings.extend(_correlate_runtime_findings(result.findings, pid, result.process_name))
        result.findings = _dedupe_findings(result.findings)[:100]
        result.memory_coverage_quality = _memory_coverage_quality(result)
        result.elapsed_seconds = round(time.monotonic() - started, 2)
        return result


def _javaw_processes() -> list[tuple[int, str]]:
    if os.name != "nt":
        return []
    kernel32 = _kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return []
    entries: list[tuple[int, str]] = []
    entry = _ProcessEntry32()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            name = entry.szExeFile.lower()
            if name == "javaw.exe":
                entries.append((int(entry.th32ProcessID), _process_executable(int(entry.th32ProcessID))))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return entries


class _ProcessEntry32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD if os.name == "nt" else ctypes.c_ulong), ("cntUsage", ctypes.c_ulong), ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong), ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_wchar * 260)]


class _ModuleEntry32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong), ("th32ProcessID", ctypes.c_ulong), ("GlblcntUsage", ctypes.c_ulong), ("ProccntUsage", ctypes.c_ulong), ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)), ("modBaseSize", ctypes.c_ulong), ("hModule", ctypes.c_void_p), ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]


class _ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ThreadID", ctypes.c_ulong),
        ("th32OwnerProcessID", ctypes.c_ulong),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
    ]


def _loaded_module_records(pid: int) -> list[dict[str, object]]:
    if os.name != "nt":
        return []
    kernel32 = _kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == INVALID_HANDLE_VALUE:
        return []
    module = _ModuleEntry32()
    module.dwSize = ctypes.sizeof(module)
    records: list[dict[str, object]] = []
    try:
        ok = kernel32.Module32FirstW(snapshot, ctypes.byref(module))
        while ok:
            if module.szExePath:
                records.append({
                    "path": module.szExePath,
                    "base": int(ctypes.cast(module.modBaseAddr, ctypes.c_void_p).value or 0),
                    "size": int(module.modBaseSize),
                })
            ok = kernel32.Module32NextW(snapshot, ctypes.byref(module))
    finally:
        kernel32.CloseHandle(snapshot)
    deduped: list[dict[str, object]] = []
    seen: set[tuple[int, str]] = set()
    for record in records:
        key = (int(record.get("base", 0) or 0), str(record.get("path", "")).lower())
        if key not in seen:
            seen.add(key)
            deduped.append(record)
    return deduped


def _loaded_modules(pid: int) -> list[str]:
    return [str(record.get("path", "")) for record in _loaded_module_records(pid) if record.get("path")]


def _expected_java_native_path(value: str) -> bool:
    normalized = value.replace("/", "\\").lower()
    file_name = normalized.rsplit("\\", 1)[-1]
    if file_name in GenericModDetector.TEMP_NATIVE_DLL_NAMES:
        return "\\native\\" in normalized or "\\natives\\" in normalized
    if re.fullmatch(r"lib\d+\.dll", file_name):
        return True
    return any(marker in normalized for marker in (
        "\\java\\bin\\", "\\jre\\bin\\", "\\jdk\\bin\\", "\\windows\\system32\\",
        "\\natives\\", "lwjgl", "glfw", "openal", "jemalloc", "jvm.dll", "java.dll",
    ))


def _pe_size_of_image(path: Path) -> int:
    """Read the PE OptionalHeader.SizeOfImage without mapping or executing it."""
    try:
        with path.open("rb") as stream:
            dos = stream.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return 0
            pe_offset = int.from_bytes(dos[0x3C:0x40], "little")
            if pe_offset < 0x40 or pe_offset > 16 * 1024 * 1024:
                return 0
            stream.seek(pe_offset)
            header = stream.read(24 + 64)
            if len(header) < 84 or header[:4] != b"PE\x00\x00":
                return 0
            optional_magic = int.from_bytes(header[24:26], "little")
            if optional_magic not in {0x10B, 0x20B}:
                return 0
            return int.from_bytes(header[24 + 56:24 + 60], "little")
    except OSError:
        return 0


def _loaded_module_integrity_findings(
    module_records: list[dict[str, object]],
    pid: int,
    process_name: str,
) -> tuple[list[ProcessFinding], int, int]:
    """Compare Toolhelp's live mapping size with the current PE on disk."""
    findings: list[ProcessFinding] = []
    checked = 0
    mismatches = 0
    for record in module_records:
        raw_path = str(record.get("path", ""))
        if not raw_path.lower().endswith((".dll", ".exe")):
            continue
        path = Path(raw_path)
        expected_native = _expected_java_native_path(raw_path)
        try:
            exists = path.is_file()
        except OSError:
            exists = False
        if not exists:
            if not expected_native:
                mismatches += 1
                findings.append(ProcessFinding(
                    pid,
                    process_name,
                    "ModuleIntegrityDetector",
                    "loaded_module_missing_on_disk",
                    "high",
                    "Loaded native module is missing on disk",
                    address=hex(int(record.get("base", 0) or 0)),
                    path=raw_path,
                    explanation="The Windows loader snapshot still contains this native image, but its backing file is no longer present. Temporary launcher natives are excluded; review deletion-after-load or replacement activity.",
                    confidence="medium",
                ))
            continue
        image_size = _pe_size_of_image(path)
        mapped_size = int(record.get("size", 0) or 0)
        if not image_size or not mapped_size:
            continue
        checked += 1
        if abs(image_size - mapped_size) <= 0x1000:
            continue
        mismatches += 1
        findings.append(ProcessFinding(
            pid,
            process_name,
            "ModuleIntegrityDetector",
            "loaded_module_disk_mismatch",
            "high",
            "Loaded module image differs from disk layout",
            address=hex(int(record.get("base", 0) or 0)),
            path=raw_path,
            explanation=f"The live module mapping is {mapped_size} bytes, while the current PE declares SizeOfImage={image_size}. The file may have been replaced after loading or the mapping may have been altered.",
            confidence="high",
        ))
    return findings, checked, mismatches


def _thread_start_addresses(pid: int) -> tuple[list[dict[str, int]], list[str]]:
    if os.name != "nt":
        return [], []
    kernel32 = _kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return [], ["Thread start-address enumeration could not create a snapshot."]
    entry = _ThreadEntry32()
    entry.dwSize = ctypes.sizeof(entry)
    starts: list[dict[str, int]] = []
    failures = 0
    try:
        ok = kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while ok:
            if int(entry.th32OwnerProcessID) == pid:
                thread_id = int(entry.th32ThreadID)
                handle = kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, thread_id)
                if handle:
                    try:
                        start_address = ctypes.c_void_p()
                        status = _ntdll().NtQueryInformationThread(handle, 9, ctypes.byref(start_address), ctypes.sizeof(start_address), None)
                        if status == 0 and start_address.value:
                            starts.append({"thread_id": thread_id, "start_address": int(start_address.value)})
                        else:
                            failures += 1
                    finally:
                        kernel32.CloseHandle(handle)
                else:
                    failures += 1
            ok = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    notes = [f"Start address was unavailable for {failures} javaw.exe thread(s)."] if failures and not starts else []
    return starts, notes


def _open_files(pid: int) -> tuple[list[str], list[str]]:
    try:
        import psutil
    except ImportError:
        return [], ["psutil is unavailable; open file handle enumeration was skipped."]
    try:
        process = psutil.Process(pid)
        paths = [item.path for item in process.open_files()]
        paths.extend(getattr(item, "path", "") for item in process.memory_maps(grouped=False))
        return _unique([path for path in paths if path]), []
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError) as exc:
        return [], [f"Open file/module mapping enumeration unavailable: {exc}"]


def _jvm_runtime_artifacts(pid: int) -> tuple[list[str], int, list[str]]:
    """Return only security-relevant JVM arguments; account/session values are never retained."""
    try:
        import psutil
        process = psutil.Process(pid)
        arguments = process.cmdline()
    except (ImportError, OSError) as exc:
        return [], 0, [f"JVM command-line inspection unavailable: {exc}"]
    except Exception as exc:  # psutil uses platform-specific exception classes
        return [], 0, [f"JVM command-line inspection unavailable: {exc}"]
    artifacts: list[str] = []
    expect_classpath = False
    for argument in arguments[1:]:
        value = str(argument).strip()
        lower = value.lower()
        if expect_classpath:
            artifacts.extend(part for part in value.split(os.pathsep) if part.lower().endswith((".jar", ".zip")))
            expect_classpath = False
            continue
        if lower in {"-cp", "-classpath"}:
            expect_classpath = True
            continue
        if lower.startswith(("-javaagent:", "-agentpath:", "-agentlib:", "-xbootclasspath", "-djava.system.class.loader=")) or lower in {"-noverify", "-xverify:none"}:
            artifacts.append(value)
            continue
        if lower.endswith((".jar", ".zip")) and ("\\" in value or "/" in value):
            artifacts.append(value)
    # These variables can inject options before the launcher command line is
    # parsed. Retain only security-relevant values; never copy the full
    # environment because it may contain tokens, passwords, or account data.
    try:
        environment = process.environ()
    except Exception:
        environment = {}
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        value = str(environment.get(key, "")).strip()
        lower = value.lower()
        if value and any(marker in lower for marker in ("-javaagent:", "-agentpath:", "-agentlib:", "-xbootclasspath")):
            artifacts.append(f"{key}={value}")
    return _unique(artifacts), max(0, len(arguments) - 1), []


def _process_executable(pid: int) -> str:
    try:
        import psutil
        return psutil.Process(pid).exe()
    except Exception:
        return ""


def _process_metadata(pid: int) -> dict[str, object]:
    """Collect non-sensitive process context used to explain scan coverage."""
    try:
        import psutil

        process = psutil.Process(pid)
        with process.oneshot():
            parent = process.parent()
            memory = process.memory_info()
            created = dt.datetime.fromtimestamp(process.create_time()).astimezone().isoformat(timespec="seconds")
            return {
                "parent_process_name": parent.name() if parent else "",
                "process_started_at": created,
                "thread_count": process.num_threads(),
                "working_set_bytes": int(getattr(memory, "rss", 0) or 0),
                "private_memory_bytes": int(getattr(memory, "private", 0) or 0),
            }
    except Exception:
        return {}


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


ASCII_JAR_PATH_RE = re.compile(rb"(?i)(?:[a-z]:\\|/)[^\x00\r\n\"<>|]{2,300}?\.jar(?:\.disabled)?")
TEXT_JAR_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|/)[^\x00\r\n\"<>|]{2,300}?\.jar(?:\.disabled)?")
ASCII_CLASS_ORIGIN_RE = re.compile(
    rb"(?i)(?:jar:)?file:(?P<jar>/{0,3}[a-z]:[/\\][^\x00\r\n\"<>|!]{1,500}?\.jar)!/"
    rb"(?P<class>(?:[a-z0-9_$.-]+/){1,30}[a-z0-9_$.-]+\.class)"
)
TEXT_CLASS_ORIGIN_RE = re.compile(
    r"(?i)(?:jar:)?file:(?P<jar>/{0,3}[a-z]:[/\\][^\x00\r\n\"<>|!]{1,500}?\.jar)!/"
    r"(?P<class>(?:[a-z0-9_$.-]+/){1,30}[a-z0-9_$.-]+\.class)"
)
SUSPICIOUS_CLASS_PATH_RE = re.compile(
    rb"(?i)(?:[a-z_$][a-z0-9_$]{0,80}[./\\]){1,12}"
    rb"[a-z0-9_$]{0,80}(?:triggerbot|killaura|autoclicker|aimassist|ghostclient|"
    rb"freecam|freelook|wallhack|autototem|maceswap|swaphelper|"
    rb"liquidbounce|meteorclient|wurstclient|vapeclient|ravenbplus|"
    rb"prestigeclient|phantomclient|slinkyclient|whiteoutclient|entropyclient|"
    rb"fdpclient|novoline|zeroday|bleachhack|rusherhack|thunderhack|grimclient|doomsdayclient)"
    rb"[a-z0-9_$]{0,80}(?:\.class)?"
)
CLASS_HINT_FAMILIES = (
    ("triggerbot", ("triggerbot",)),
    ("killaura", ("killaura",)),
    ("autoclicker", ("autoclicker",)),
    ("aimassist", ("aimassist",)),
    ("freecam", ("freecam",)),
    ("freelook", ("freelook",)),
    ("xray", ("wallhack",)),
    ("autototem", ("autototem",)),
    ("maceswap", ("maceswap", "swaphelper")),
)


def _jar_artifact_paths(values: Iterable[str]) -> list[str]:
    paths: list[str] = []
    for raw in values:
        value = str(raw).strip().strip('"')
        lower = value.lower()
        if lower.startswith(("-javaagent:", "-agentpath:")):
            value = value.split(":", 1)[1]
            lower = value.lower()
        if ".jar" not in lower:
            continue
        # Classpath arguments may contain multiple entries.
        for part in re.split(r"[;\n\r]", value):
            candidate = part.strip().strip('"')
            if re.search(r"(?i)\.jar(?:\.disabled)?$", candidate):
                paths.append(_normalize_extracted_jar_path(candidate))
    return _unique(paths)[:300]


def _normalize_extracted_jar_path(value: str) -> str:
    candidate = unquote(str(value).strip().strip('"'))
    for prefix in ("jar:file:", "file:"):
        if candidate.lower().startswith(prefix):
            candidate = candidate[len(prefix):]
            break
    # Java URLClassLoader commonly renders Windows paths as /C:/path/mod.jar.
    if re.match(r"^/[a-z]:[/\\]", candidate, re.IGNORECASE):
        candidate = candidate[1:]
    return candidate


def _extract_memory_jar_paths(data: bytes, limit: int = 200) -> list[str]:
    """Extract path-shaped JAR strings without retaining surrounding memory."""
    found: list[str] = []
    for match in ASCII_JAR_PATH_RE.finditer(data):
        value = _normalize_extracted_jar_path(match.group().decode("utf-8", errors="ignore"))
        if value and value not in found:
            found.append(value)
        if len(found) >= limit:
            return found
    if b".\x00j\x00a\x00r\x00" in data.lower():
        text = data.decode("utf-16le", errors="ignore")
        for match in TEXT_JAR_PATH_RE.finditer(text):
            value = _normalize_extracted_jar_path(match.group())
            if value and value not in found:
                found.append(value)
            if len(found) >= limit:
                break
    return found


def _extract_memory_class_origins(data: bytes, base_address: int = 0, limit: int = 200) -> list[dict[str, object]]:
    """Extract explicit ClassLoader resource URLs without attaching an agent."""
    found: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    def add(jar_value: str, class_entry: str, address: int, encoding: str) -> None:
        jar_path = _normalize_extracted_jar_path(jar_value)
        entry = class_entry.replace("\\", "/")
        key = (_normalized_windows_path(jar_path), entry.lower())
        if not jar_path or not entry or key in seen or len(found) >= limit:
            return
        seen.add(key)
        found.append({
            "jar_path": jar_path,
            "class_entry": entry,
            "class_name": entry[:-6].replace("/", ".") if entry.lower().endswith(".class") else entry.replace("/", "."),
            "address": hex(address),
            "encoding": encoding,
            "on_disk": False,
            "class_present_on_disk": None,
        })

    for match in ASCII_CLASS_ORIGIN_RE.finditer(data):
        add(match.group("jar").decode("utf-8", errors="ignore"), match.group("class").decode("ascii", errors="ignore"), base_address + match.start(), "latin1")
        if len(found) >= limit:
            return found

    if b".\x00j\x00a\x00r\x00" in data.lower() or b"j\x00a\x00r\x00:\x00f\x00i\x00l\x00e\x00" in data.lower():
        for byte_offset in (0, 1):
            text = data[byte_offset:].decode("utf-16le", errors="ignore")
            for match in TEXT_CLASS_ORIGIN_RE.finditer(text):
                add(match.group("jar"), match.group("class"), base_address + byte_offset + match.start() * 2, "utf-16le")
                if len(found) >= limit:
                    return found
    return found


def _verify_class_origins(origins: list[dict[str, object]]) -> list[dict[str, object]]:
    verified = [dict(origin) for origin in origins]
    groups: dict[str, list[dict[str, object]]] = {}
    for origin in verified:
        groups.setdefault(str(origin.get("jar_path", "")), []).append(origin)
    for jar_path, items in groups.items():
        path = Path(jar_path)
        exists = path.is_file()
        for item in items:
            item["on_disk"] = exists
        if not exists:
            continue
        try:
            with zipfile.ZipFile(path) as archive:
                names = {info.filename.replace("\\", "/").lower() for info in archive.infolist()}
            for item in items:
                item["class_present_on_disk"] = str(item.get("class_entry", "")).lower() in names
        except (OSError, zipfile.BadZipFile):
            for item in items:
                item["class_present_on_disk"] = None
    return verified


def _class_origin_findings(origins: list[dict[str, object]], pid: int, process_name: str) -> list[ProcessFinding]:
    findings: list[ProcessFinding] = []
    for origin in origins:
        jar_path = str(origin.get("jar_path", ""))
        class_name = str(origin.get("class_name", ""))
        identities = find_client_name_matches([Path(jar_path).name, class_name])
        families = _runtime_families(f"{jar_path} {class_name}")
        if identities or families:
            indicator = identities[0].family if identities else sorted(families)[0]
            disk_state = origin.get("class_present_on_disk")
            verification = "The class entry is present in the source JAR on disk." if disk_state is True else "The source URL was recovered from JVM memory; the disk entry could not be confirmed."
            findings.append(ProcessFinding(
                pid,
                process_name,
                "RuntimeClassOriginDetector",
                "class_jar_attribution",
                "high",
                f"{indicator} runtime class origin",
                address=str(origin.get("address", "")),
                path=f"{jar_path}!/{origin.get('class_entry', '')}",
                explanation=f"A JVM ClassLoader resource ties {class_name} to this JAR. {verification}",
                confidence="high" if disk_state is True else "medium",
            ))
        if origin.get("on_disk") is True and origin.get("class_present_on_disk") is False:
            suspicious = bool(identities or families)
            findings.append(ProcessFinding(
                pid,
                process_name,
                "RuntimeClassOriginDetector",
                "runtime_class_disk_mismatch",
                "high" if suspicious else "medium",
                "Runtime class source differs from disk JAR",
                address=str(origin.get("address", "")),
                path=f"{jar_path}!/{origin.get('class_entry', '')}",
                explanation="The JVM memory contains an explicit class-to-JAR resource URL, but that class entry is no longer present in the current disk JAR. The JAR may have changed after launch or the URL may be stale; review is required.",
                confidence="medium",
            ))
    return findings


def _extract_suspicious_class_hints(data: bytes, limit: int = 40) -> list[tuple[str, str, int]]:
    """Return class-shaped feature/client strings and their offsets only.

    Bare words are deliberately excluded: the value must resemble a Java
    package/class path, reducing matches from chat, translations and logs.
    """
    found: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for match in SUSPICIOUS_CLASS_PATH_RE.finditer(data):
        raw = match.group().decode("ascii", errors="ignore")
        class_path = raw.replace("\\", ".").replace("/", ".").strip(".")
        compact = re.sub(r"[^a-z0-9]", "", class_path.lower())
        family = next((name for name, aliases in CLASS_HINT_FAMILIES if any(alias in compact for alias in aliases)), "")
        if not family:
            identities = find_client_name_matches([class_path])
            family = identities[0].family if identities else "known-client"
        key = class_path.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append((class_path, family, match.start()))
        if len(found) >= limit:
            break
    return found


def _looks_like_pe_image(data: bytes) -> bool:
    if len(data) < 0x44 or data[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(data[0x3C:0x40], "little", signed=False)
    return 0x40 <= pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00"


def _memory_type_label(memory_type: int) -> str:
    return {
        MEM_PRIVATE: "MEM_PRIVATE",
        MEM_IMAGE: "MEM_IMAGE",
        0x40000: "MEM_MAPPED",
    }.get(int(memory_type), hex(int(memory_type)) if memory_type else "")


def _protection_label(protection: int) -> str:
    base = int(protection) & 0xFF
    label = {
        0x01: "NOACCESS",
        0x02: "R",
        0x04: "RW",
        0x08: "RWCOPY",
        0x10: "X",
        0x20: "RX",
        0x40: "RWX",
        0x80: "RXCOPY",
    }.get(base, hex(base) if base else "")
    if int(protection) & PAGE_GUARD:
        label += "+GUARD"
    return label


def _thread_private_exec_matches(thread_starts: list[dict[str, int]], regions: list[_ReadableRegion]) -> list[dict[str, int]]:
    matches: list[dict[str, int]] = []
    for thread in thread_starts:
        start = int(thread.get("start_address", 0) or 0)
        region = next((item for item in regions if item.base <= start < item.base + item.size), None)
        if region:
            matches.append({
                "thread_id": int(thread.get("thread_id", 0) or 0),
                "start_address": start,
                "region_base": region.base,
                "allocation_base": region.allocation_base or region.base,
            })
    return matches


def _native_memory_findings(
    pid: int,
    process_name: str,
    private_exec_regions: list[_ReadableRegion],
    hidden_pe_allocations: set[int],
    unlisted_image_allocations: set[int],
    thread_starts: list[dict[str, int]],
) -> tuple[list[ProcessFinding], list[dict[str, int]]]:
    findings: list[ProcessFinding] = []
    thread_matches = _thread_private_exec_matches(thread_starts, private_exec_regions)
    thread_allocations = {int(item["allocation_base"]) for item in thread_matches}
    correlated = hidden_pe_allocations.intersection(thread_allocations)
    for allocation in sorted(correlated):
        threads = [str(item["thread_id"]) for item in thread_matches if int(item["allocation_base"]) == allocation]
        findings.append(ProcessFinding(
            pid,
            process_name,
            "ManualMapDetector",
            "manual_map_correlation",
            "critical",
            "Private executable PE with native thread",
            address=hex(allocation),
            path=f"Thread(s): {', '.join(threads[:8])}",
            explanation="A valid PE image exists in executable MEM_PRIVATE memory outside the normal loader module list, and a process thread starts inside the same private allocation. This multi-signal correlation is a strong manual-map indicator.",
            confidence="high",
        ))
    for allocation in sorted(hidden_pe_allocations - correlated):
        findings.append(ProcessFinding(
            pid,
            process_name,
            "ManualMapDetector",
            "private_executable_pe",
            "high",
            "PE image in executable private memory",
            address=hex(allocation),
            explanation="A valid MZ/PE image header was recovered from an executable MEM_PRIVATE allocation that is not represented as a normal loaded module. Packers can also create this layout, so thread and artifact context matters.",
            confidence="high",
        ))
    for item in thread_matches:
        allocation = int(item["allocation_base"])
        if allocation in correlated:
            continue
        findings.append(ProcessFinding(
            pid,
            process_name,
            "ManualMapDetector",
            "private_exec_thread_start",
            "high",
            "Thread starts in executable private memory",
            address=hex(int(item["start_address"])),
            path=f"Thread {item['thread_id']} | allocation {hex(allocation)}",
            explanation="A javaw.exe thread begins inside executable MEM_PRIVATE memory instead of a normal MEM_IMAGE module. This is uncommon for standard JVM threads and requires native-injection review.",
            confidence="medium",
        ))
    for allocation in sorted(unlisted_image_allocations)[:20]:
        findings.append(ProcessFinding(
            pid,
            process_name,
            "HiddenImageDetector",
            "unlisted_image_mapping",
            "medium",
            "Executable image mapping absent from module snapshot",
            address=hex(allocation),
            explanation="A MEM_IMAGE allocation was visible in the process memory map but its allocation base was absent from the Toolhelp module snapshot. This can be a transient or loader-specific mapping and is a contextual signal only.",
            confidence="low",
        ))
    return findings, thread_matches


def _normalized_windows_path(value: str) -> str:
    return os.path.normcase(os.path.normpath(str(value).strip().strip('"')))


def _runtime_mod_candidate(path: str) -> bool:
    lower = path.replace("/", "\\").lower()
    name = lower.rsplit("\\", 1)[-1]
    if "\\mods\\" in lower:
        return True
    if any(marker in lower for marker in ("\\temp\\", "\\downloads\\")):
        return bool(find_client_name_matches([name])) or any(
            token in re.sub(r"[^a-z0-9]", "", name)
            for token in ("freecam", "freelook", "autoclicker", "triggerbot", "killaura", "autototem", "maceswap", "swaphelper")
        )
    return False


def _runtime_jar_details(runtime_jars: list[str], memory_jars: list[str], artifacts: list[str]) -> list[dict[str, object]]:
    memory_paths = {_normalized_windows_path(path) for path in memory_jars}
    artifact_paths = {_normalized_windows_path(path) for path in _jar_artifact_paths(artifacts)}
    details: list[dict[str, object]] = []
    for raw_path in runtime_jars[:300]:
        normalized = _normalized_windows_path(raw_path)
        sources: list[str] = []
        if normalized in artifact_paths:
            sources.append("open file / classpath")
        if normalized in memory_paths:
            sources.append("JVM memory")
        path = Path(raw_path)
        exists = False
        size = 0
        sha256 = ""
        try:
            exists = path.is_file()
            size = path.stat().st_size if exists else 0
            # Hash runtime mod candidates, not the full launcher library set.
            if exists and size <= 512 * 1024 * 1024 and _runtime_mod_candidate(raw_path):
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                sha256 = digest.hexdigest()
        except OSError:
            exists = False
            size = 0
        lower = raw_path.replace("/", "\\").lower()
        location = "mods" if "\\mods\\" in lower else "temp" if "\\temp\\" in lower else "library" if "\\libraries\\" in lower else "other"
        details.append({
            "path": raw_path,
            "sources": sources or ["runtime artifact"],
            "exists": exists,
            "size": size,
            "sha256": sha256,
            "location": location,
            "installed_match": None,
        })
    return details


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _runtime_jar_probe_findings(
    details: list[dict[str, object]],
    pid: int,
    process_name: str,
    max_jars: int = 40,
) -> tuple[list[ProcessFinding], int]:
    """Perform a bounded structural probe of JARs proven to be loaded by the JVM.

    This is intentionally narrower than Mod Scan: it only looks for a correlated
    concealed-loader shape and never flags a Java agent, JNA dependency, or packed
    resource on its own.
    """
    findings: list[ProcessFinding] = []
    probed = 0
    for detail in details:
        if probed >= max_jars:
            break
        raw_path = str(detail.get("path", ""))
        # Probe every non-library JAR proven to be active in the JVM. A renamed
        # agent can be launched from Downloads/Temp and deliberately avoid a
        # mod-looking filename; path semantics must not be the gate here.
        if not detail.get("exists") or str(detail.get("location", "other")) == "library":
            continue
        path = Path(raw_path)
        try:
            if path.stat().st_size > 512 * 1024 * 1024:
                continue
        except OSError:
            continue
        probed += 1
        agent_manifest = False
        retransform = False
        direct_class_loader = False
        native_memory_bridge = False
        raw_payload_io = False
        opaque_paths: list[str] = []
        class_budget = 16 * 1024 * 1024
        class_bytes = 0
        try:
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()[:20000]
                manifest_info = next((item for item in infos if item.filename.replace("\\", "/").lower() == "meta-inf/manifest.mf"), None)
                if manifest_info and manifest_info.file_size <= 1024 * 1024:
                    manifest = archive.read(manifest_info).lower()
                    agent_manifest = b"premain-class:" in manifest or b"agent-class:" in manifest
                    retransform = b"can-retransform-classes: true" in manifest
                for info in infos:
                    if info.is_dir():
                        continue
                    normalized = info.filename.replace("\\", "/").strip("/")
                    lower_name = normalized.lower()
                    base = normalized.rsplit("/", 1)[-1]
                    if (
                        info.file_size >= 4096
                        and "." not in base
                        and not lower_name.startswith(("meta-inf/", "assets/", "data/"))
                        and len(opaque_paths) < 20
                    ):
                        with archive.open(info, "r") as stream:
                            sample = stream.read(64 * 1024)
                        if _byte_entropy(sample) >= 7.6:
                            opaque_paths.append(normalized)
                    if not lower_name.endswith(".class") or info.file_size > 2 * 1024 * 1024 or class_bytes >= class_budget:
                        continue
                    data = archive.read(info)
                    class_bytes += len(data)
                    lowered = data.lower()
                    if b"defineclass" in lowered and b"classloader" in lowered:
                        direct_class_loader = True
                    if (
                        b"nativelibrary" in lowered
                        and (b"com/sun/jna/pointer" in lowered or b"com/sun/jna/memory" in lowered)
                        and (b"runtime" in lowered and b"exec" in lowered or b"processbuilder" in lowered or b"system" in lowered and b"load" in lowered)
                    ):
                        native_memory_bridge = True
                    if b"socketchannel" in lowered and b"randomaccessfile" in lowered and b"getresourceasstream" in lowered:
                        raw_payload_io = True
        except (OSError, RuntimeError, zipfile.BadZipFile, KeyError):
            detail["structural_probe"] = {"status": "unreadable"}
            continue

        probe = {
            "status": "complete",
            "agent_manifest": agent_manifest,
            "class_retransform": retransform,
            "direct_class_loader": direct_class_loader,
            "native_memory_bridge": native_memory_bridge,
            "raw_payload_io": raw_payload_io,
            "high_entropy_opaque_payloads": len(opaque_paths),
            "opaque_paths": opaque_paths[:10],
        }
        detail["structural_probe"] = probe
        correlated_loader = direct_class_loader and native_memory_bridge and len(opaque_paths) >= 3
        if not correlated_loader:
            continue
        decisive = agent_manifest and retransform and raw_payload_io
        findings.append(ProcessFinding(
            pid,
            process_name,
            "RuntimeJarStructureDetector",
            "runtime_concealed_loader" if decisive else "runtime_opaque_loader",
            "critical" if decisive else "high",
            "Loaded JAR contains a concealed payload-loader chain",
            path=raw_path,
            explanation=(
                f"This JAR is active in javaw.exe and independently contains {len(opaque_paths)} high-entropy extensionless payloads, "
                "direct ClassLoader.defineClass logic, and a JNA native-memory/process bridge"
                + (", plus a retransformation-capable Java Agent and raw socket/file payload I/O." if decisive else ".")
            ),
            confidence="high",
        ))
    return findings, probed


def _compare_runtime_to_disk(result: JavaProcessScanResult, installed_mod_paths: list[Path]) -> None:
    installed_paths = {_normalized_windows_path(str(path)) for path in installed_mod_paths}
    installed_names = {path.name.lower() for path in installed_mod_paths}
    result.disk_mod_jars = sorted((str(path) for path in installed_mod_paths), key=str.lower)[:500]
    runtime_only: list[str] = []
    for runtime_path in result.runtime_jars:
        if not _runtime_mod_candidate(runtime_path):
            continue
        normalized = _normalized_windows_path(runtime_path)
        file_name = Path(runtime_path).name.lower()
        if normalized in installed_paths or file_name in installed_names:
            continue
        runtime_only.append(runtime_path)
    result.runtime_only_jars = _unique(runtime_only)[:100]
    runtime_only_normalized = {_normalized_windows_path(path) for path in result.runtime_only_jars}
    for detail in result.runtime_jar_details:
        normalized = _normalized_windows_path(str(detail.get("path", "")))
        detail["installed_match"] = normalized not in runtime_only_normalized if _runtime_mod_candidate(str(detail.get("path", ""))) else None
    for path in result.runtime_only_jars:
        missing = not Path(path).is_file()
        result.findings.append(ProcessFinding(
            result.pid,
            result.process_name,
            "DiskMemoryComparator",
            "runtime_only_jar",
            "high" if missing else "medium",
            "Runtime-only mod/JAR",
            path=path,
            explanation=(
                "A mod-shaped JAR path is present in JVM runtime evidence but is absent from the discovered mods folders and no longer exists on disk."
                if missing
                else "A mod-shaped JAR is loaded by the JVM but is outside the discovered instance mods inventory."
            ),
        ))


def _dedupe_findings(findings: list[ProcessFinding]) -> list[ProcessFinding]:
    out: list[ProcessFinding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in findings:
        key = (item.detector, item.finding_type, item.address or item.indicator.lower(), item.path.lower())
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


RUNTIME_FAMILY_ALIASES = {
    "freecam": ("freecam", "free look", "freelook"),
    "xray": ("xray", "wallhack"),
    "autototem": ("auto-totem", "autototem", "totem"),
    "maceswap": ("mace/swap", "maceswap", "swaphelper", "swap helper"),
    "reach": ("reach helper", "reach"),
    "mousetweaks": ("mousetweaks", "mouse tweaks"),
    "autoclicker": ("autoclicker", "auto clicker"),
    "triggerbot": ("triggerbot", "trigger bot"),
    "killaura": ("killaura", "kill aura"),
}


def _runtime_families(value: str) -> set[str]:
    lower = value.lower()
    return {family for family, aliases in RUNTIME_FAMILY_ALIASES.items() if any(alias in lower for alias in aliases)}


def _correlate_runtime_findings(findings: list[ProcessFinding], pid: int, process_name: str) -> list[ProcessFinding]:
    artifact_families: dict[str, list[ProcessFinding]] = {}
    memory_families: dict[str, list[ProcessFinding]] = {}
    for finding in findings:
        families = _runtime_families(f"{finding.indicator} {finding.path} {finding.explanation}")
        target = memory_families if finding.finding_type in {"memory_signature", "memory_class_hint"} else artifact_families
        for family in families:
            target.setdefault(family, []).append(finding)
    correlations: list[ProcessFinding] = []
    for family in sorted(set(artifact_families).intersection(memory_families)):
        artifact = artifact_families[family][0]
        memory = memory_families[family][0]
        correlations.append(ProcessFinding(
            pid,
            process_name,
            "RuntimeCorrelationDetector",
            "artifact_memory_correlation",
            "critical" if family in {"autoclicker", "triggerbot", "killaura", "xray", "maceswap"} else "high",
            family,
            address=memory.address,
            path=artifact.path,
            explanation=f"The same {family} indicator appears in a JVM memory region and an open/loaded runtime artifact. This correlation is stronger than either signal alone.",
            confidence="high",
        ))
    return correlations


def _memory_coverage_quality(result: JavaProcessScanResult) -> str:
    if result.memory_scan_stop_reason == "unavailable" or result.scanned_bytes <= 0:
        return "Unavailable"
    failure_percent = (result.memory_read_failures / result.memory_read_attempts) if result.memory_read_attempts else 0.0
    if failure_percent >= 0.20 or result.successful_regions < max(1, result.scanned_regions // 2):
        return "Partial"
    completion_ratio = (result.memory_completed_chunks / result.memory_planned_chunks) if result.memory_planned_chunks else 0.0
    if result.memory_scan_stop_reason == "balanced sample completed" and completion_ratio >= 0.90:
        return "Balanced sample"
    if result.memory_scan_stop_reason in {"time budget reached", "byte limit reached", "memory map discovery timed out"}:
        return "Limited"
    if result.memory_scan_stop_reason in {"memory map completed", "address space exhausted", "completed"}:
        return "Complete map"
    return "Partial"


def _calibrate_process_findings(findings: list[ProcessFinding]) -> list[ProcessFinding]:
    """Calibrate severity separately from confidence using independent evidence."""
    correlated = {
        family
        for finding in findings
        if finding.finding_type == "artifact_memory_correlation"
        for family in _runtime_families(f"{finding.indicator} {finding.path}")
    }
    for finding in findings:
        families = _runtime_families(f"{finding.indicator} {finding.path} {finding.explanation}")
        has_correlation = bool(families.intersection(correlated))
        if finding.finding_type == "artifact_memory_correlation":
            finding.confidence = "high"
            finding.evidence_score = 95
        elif finding.finding_type == "runtime_concealed_loader":
            finding.confidence = "high"
            finding.evidence_score = 99
        elif finding.finding_type == "runtime_opaque_loader":
            finding.confidence = "high"
            finding.evidence_score = 93
        elif finding.finding_type == "loaded_module_disk_mismatch":
            finding.confidence = "high"
            finding.evidence_score = 94
        elif finding.finding_type == "loaded_module_missing_on_disk":
            finding.confidence = "medium"
            finding.evidence_score = 84
        elif finding.finding_type == "manual_map_correlation":
            finding.confidence = "high"
            finding.evidence_score = 98
        elif finding.finding_type == "private_executable_pe":
            finding.confidence = "high"
            finding.evidence_score = 92
        elif finding.finding_type == "private_exec_thread_start":
            finding.confidence = "medium"
            finding.evidence_score = 82
        elif finding.finding_type == "unlisted_image_mapping":
            finding.confidence = "low"
            finding.evidence_score = 35
        elif finding.finding_type == "class_jar_attribution":
            finding.evidence_score = 92 if finding.confidence == "high" else 78
        elif finding.finding_type == "runtime_class_disk_mismatch":
            finding.evidence_score = 82 if finding.severity == "high" else 58
        elif finding.finding_type == "runtime_only_jar":
            finding.confidence = "high" if not Path(finding.path).is_file() else "medium"
            finding.evidence_score = 90 if finding.confidence == "high" else 65
        elif finding.finding_type == "known_client_artifact":
            finding.confidence = "high"
            finding.evidence_score = 90
        elif finding.finding_type in {"restricted_mod_artifact", "jvm_agent", "environment_jvm_injection"}:
            finding.confidence = "high" if has_correlation else "medium"
            finding.evidence_score = 88 if has_correlation else (75 if finding.finding_type == "environment_jvm_injection" else 60)
        elif finding.finding_type == "memory_class_hint":
            finding.confidence = "high" if has_correlation else "medium"
            finding.evidence_score = 88 if has_correlation else 55
        elif finding.finding_type == "memory_signature":
            if has_correlation:
                finding.confidence = "high"
                finding.evidence_score = 88
            elif finding.detector in {"GenericModDetector", "RestrictedModDetector"}:
                finding.confidence = "low"
                finding.evidence_score = 20
                if finding.severity in {"high", "critical"}:
                    finding.severity = "medium"
                if "Memory-only text" not in finding.explanation:
                    finding.explanation += " Memory-only text is not proof and was lowered because no matching runtime artifact or class-path evidence was found."
            else:
                finding.confidence = "medium"
                finding.evidence_score = 70 if finding.detector == "DoomsdayDetector" else 60
        elif finding.finding_type == "unusual_loaded_dll":
            finding.confidence = "low"
            finding.evidence_score = 25
        else:
            finding.evidence_score = {"high": 75, "medium": 50, "low": 25}.get(finding.confidence, 25)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda item: (-item.evidence_score, severity_order.get(item.severity, 5), confidence_order.get(item.confidence, 3), item.detector, item.indicator.lower()))


@lru_cache(maxsize=1)
def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Thread32Next.restype = wintypes.BOOL
    return kernel32


@lru_cache(maxsize=1)
def _ntdll():
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtQueryInformationThread.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    ntdll.NtQueryInformationThread.restype = ctypes.c_long
    return ntdll
