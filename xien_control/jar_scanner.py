from __future__ import annotations

import datetime as dt
import io
import json
import re
import sys
import tomllib
import zipfile
import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable

from .archive_identifier import identify_java_archive, is_nested_archive_name
from .bytecode import BytecodeAnalysis, analyze_class_bytecode
from .cache_manager import AnalysisCache, RULES_VERSION
from .class_attributes import ClassAttributeSummary, parse_class_attributes
from .class_roles import classify_class_role
from .class_strings import (
    extract_printable_strings,
    keyword_matches,
    keyword_matches_index,
    ngrams,
    parse_class_constants,
    path_tokens,
    prepare_text,
    tokens_for_text,
)
from .client_names import find_client_name_matches
from .dependency_graph import collect_dependency_metadata
from .descriptor_parser import descriptor_contexts
from .explain import confidence_explanations
from .fingerprint import build_fingerprints
from .graph_analysis import analyze_class_graph
from .local_lists import load_allowlist, load_known_hashes
from .mapping_hints import MappingHints
from .mixin_analysis import analyze_mixin_annotations, record_annotation_context
from .models import DetectionMatch, JarScanResult, LauncherLocation, Rule
from .numeric_constants import analyze_numeric_context, extract_numbers_from_text
from .opcode_summary import opcode_activity_score
from .package_classifier import classify_packages
from .reachability import analyze_reachability
from .risk import calculate_jar_risk
from .rules import load_rules
from .signature_integrity import analyze_signature_integrity
from .string_decode import decoded_variants
from .utils import human_size, is_randomish_name, is_safe_looking_name, safe_mtime, sha256_file
from .vector_scoring import compute_token_vectors
from .zip_anomalies import analyze_zip_structure


LogFn = Callable[[str, str], None]

MAX_JAR_ENTRIES = 65000
MAX_CLASS_BYTES_PER_JAR = 160 * 1024 * 1024
MAX_SINGLE_CLASS_BYTES = 2 * 1024 * 1024
MAX_DETECTIONS_PER_RULE_SOURCE = 6
MAX_EVIDENCE_PREVIEW = 220
MAX_CONFIG_FILES_PER_JAR = 80
MAX_NESTED_DEPTH = 2
MAX_NESTED_JARS = 50
DEEP_AUDIT_SAMPLE_BYTES = 64 * 1024
OPAQUE_RESOURCE_SAMPLE_BYTES = 256 * 1024
OPAQUE_RESOURCE_MIN_BYTES = 4 * 1024
DEEP_AUDIT_FEATURE_MARKERS = (
    ("triggerbot", "high"),
    ("killaura", "high"),
    ("autoclicker", "high"),
    ("freecam", "high"),
    ("freelook", "high"),
    ("wallhack", "high"),
    ("xray", "high"),
    ("autototem", "high"),
    ("auto-totem", "high"),
    ("swaphelper", "high"),
    ("maceswap", "high"),
    ("mousetweaks", "low"),
)
DEEP_AUDIT_ACTIVE_SUFFIXES = (
    ".class", ".java", ".kt", ".kts", ".json", ".toml", ".properties",
    ".cfg", ".conf", ".yml", ".yaml", ".txt",
)
DEEP_AUDIT_IGNORED_PATH_PARTS = (
    "/lang/", "/translations/", "/docs/", "/doc/", "/licenses/",
    "/license/", "/changelog/", "/notice/", "readme", "license",
    "changelog", "notice",
)

STRONG_BYTECODE_BEHAVIOR_RULES = {
    "BYTECODE_TBOT_AUTOMATION", "BYTECODE_SELF_RESTORE_OVERWRITE", "BYTECODE_SELF_DELETE",
    "BYTECODE_SELF_DESTRUCT_COMMAND", "BYTECODE_SELF_DESTRUCT_SHUTDOWN", "BYTECODE_JUMPRESET_BEHAVIOR",
    "BYTECODE_AIMASSIST_BEHAVIOR", "BYTECODE_REACH_BEHAVIOR",
    "BYTECODE_VELOCITY_BEHAVIOR", "BYTECODE_AUTOCLICKER_BEHAVIOR",
    "BYTECODE_ENCRYPTED_JAR_LOADER", "BYTECODE_REMOTE_PAYLOAD_LOADER", "BYTECODE_HWID_REMOTE_LOADER",
    "BYTECODE_NATIVE_MEMORY_LOADER_BRIDGE", "BYTECODE_CONCEALED_AGENT_PAYLOAD_LOADER",
    "BYTECODE_CONNECTED_OPAQUE_LOADER_GRAPH",
    "DOOMSDAY_STRUCTURAL_FAMILY",
}

METADATA_FILES = {
    "fabric.mod.json",
    "quilt.mod.json",
    "META-INF/mods.toml",
    "mcmod.info",
    "META-INF/MANIFEST.MF",
}
METADATA_FILES_LOWER = {item.lower() for item in METADATA_FILES}

HARD_PACKAGE_TOKENS = {
    "bypass",
    "cheat",
    "exploit",
    "ghost",
    "hack",
    "hacks",
}

SOFT_PACKAGE_TOKENS = {
    "combat",
    "feature",
    "features",
    "module",
    "modules",
    "movement",
    "player",
    "render",
    "world",
}

WEAK_CONTEXT_KEYWORDS = {
    "anticheat",
    "anti cheat",
    "bypass",
    "esp",
    "fly",
    "inject",
    "injector",
    "jesus",
    "long jump",
    "longjump",
    "phase",
    "reach",
    "spider",
    "speed",
    "tower",
    "velocity",
    "x ray",
    "x-ray",
}

MATCH_CONTEXT_TOKENS = {
    "aura",
    "bind",
    "cheat",
    "clickgui",
    "combat",
    "enabled",
    "feature",
    "features",
    "ghost",
    "hack",
    "hacks",
    "keybind",
    "mode",
    "module",
    "modules",
    "movement",
    "render",
    "setting",
    "settings",
    "toggle",
}

CONFIG_SUFFIXES = (".json", ".toml", ".properties", ".txt", ".cfg", ".conf", ".yml", ".yaml")
MAX_CONFIG_BYTES = 256 * 1024
ASSET_DATA_PATH_MARKERS = (
    "assets/",
    "data/",
    "lang/",
    "recipes/",
    "advancements/",
    "loot_tables/",
    "models/",
    "blockstates/",
    "textures/",
    "sounds/",
)
BUILD_METADATA_MARKERS = (
    "pom.properties",
    "pom.xml",
    "build.gradle",
    "gradle.properties",
    "license",
    "readme",
    "meta-inf/maven/",
)
CONFIG_PATH_HINTS = (
    "config",
    "setting",
    "settings",
    "default",
    "module",
    "modules",
    "client",
    "feature",
    "features",
    "profile",
)

MIXIN_FILE_RE = re.compile(r"(^|/)(mixins[^/]*\.json|[^/]*\.mixins\.json)$", re.IGNORECASE)
LANG_FILE_RE = re.compile(r"(^|/)assets/.+/lang/.+\.(json|lang)$", re.IGNORECASE)
SERVICE_PREFIX = "meta-inf/services/"

MIXIN_TARGET_TOKENS = {
    "minecraftclient",
    "clientplayerentity",
    "playerentity",
    "livingentity",
    "gamerenderer",
    "mouse",
    "keyboard",
    "clientconnection",
    "clientplaynetworkhandler",
    "entityrenderer",
    "worldrenderer",
    "keybinding",
    "entity",
}

FEATURE_CONTEXT_TOKENS = {
    "aimassist",
    "aimbot",
    "antikb",
    "autoclicker",
    "baritone",
    "crystalaura",
    "esp",
    "fullbright",
    "ghostclient",
    "jesus",
    "killaura",
    "longjump",
    "nametags",
    "noclip",
    "reach",
    "scaffold",
    "triggerbot",
    "velocity",
    "wallhack",
    "xray",
}

MODULE_MANAGER_TOKENS = {
    "feature",
    "featuremanager",
    "manager",
    "module",
    "modulemanager",
    "modules",
    "registry",
}

GUI_SETTING_TOKENS = {
    "cps",
    "enabled",
    "invisibles",
    "mode",
    "players",
    "range",
    "rotation",
    "silent",
    "smooth",
    "targets",
    "walls",
}

CHEAT_GUI_FEATURE_CONTROLS = {
    "aimassist": {"rotation", "silent", "smooth", "targets", "walls"},
    "aimbot": {"rotation", "silent", "smooth", "targets", "walls"},
    "autoclicker": {"cps", "range", "targets"},
    "crystalaura": {"range", "rotation", "targets", "walls"},
    "killaura": {"range", "rotation", "silent", "targets", "walls"},
    "reach": {"range", "targets", "walls"},
    "triggerbot": {"cps", "range", "targets", "walls"},
    "velocity": {"mode"},
}

BENIGN_PREFIX_TOKENS = {
    "architectury",
    "embeddedt",
    "fabricmc",
    "lambdaurora",
    "shedaniel",
    "teamreborn",
    "terraformersmc",
    "vazkii",
    "xaero",
}

METHOD_FIELD_SIGNALS = {
    "onattack",
    "ontick",
    "onupdate",
    "onrender",
    "onpacket",
    "getreach",
    "setreach",
    "autoclick",
    "doclick",
    "attackentity",
    "getcps",
    "setvelocity",
    "noslow",
    "keepsprint",
    "targetstrafe",
    "isbot",
    "gettargets",
    "disablehurtcam",
    "changehurtcamtype",
    "tiltviewwhenhurt",
    "getdamagetiltyaw",
}

MINECRAFT_API_MARKERS = {
    "clienttickevents",
    "hudrendercallback",
    "worldrenderevents",
    "attackentitycallback",
    "useitemcallback",
    "clientplaynetworking",
    "clientconnection",
    "clientplayerentity",
    "minecraftclient",
    "entityhitresult",
    "playerentity",
    "livingentity",
    "keybinding",
    "mouse",
    "gamerenderer",
    "matrixstack",
}

PACKAGE_ROLE_TOKENS = {
    "combat",
    "movement",
    "render",
    "player",
    "world",
    "exploit",
    "module",
    "modules",
    "feature",
    "features",
    "client",
    "ghost",
    "hack",
}


class JarScanner:
    def __init__(self, log: LogFn | None = None, cache_dir: Path | None = None, enable_cache: bool = True):
        self.log = log or (lambda _tag, _msg: None)
        self.search_roots = self._local_search_roots()
        self.rules = load_rules(self.search_roots)
        self.known_hashes = load_known_hashes(self.search_roots)
        self.allowlist = load_allowlist(self.search_roots)
        self.cache_dir = cache_dir or self._default_cache_dir()
        self.cache = AnalysisCache(self.cache_dir) if enable_cache else None
        self.mapping_hints = MappingHints(self.search_roots)

    def scan(self, jar_path: Path, location: LauncherLocation, precomputed_sha256: str | None = None) -> JarScanResult:
        stat = jar_path.stat()
        last_modified = dt.datetime.fromtimestamp(stat.st_mtime).replace(microsecond=0)
        sha256 = precomputed_sha256 or sha256_file(jar_path)
        if self.cache:
            cached = self.cache.get(jar_path, sha256, stat.st_size, last_modified)
            if cached:
                cached.launcher_name = location.launcher_name
                cached.instance_name = location.instance_name
                cached.instance_context = self._instance_context(location, cached)
                self.log("CACHE", f"reused analysis for {jar_path.name}")
                return cached

        _is_archive, archive_type = identify_java_archive(jar_path, broad=True)
        result = JarScanResult(
            path=jar_path,
            file_name=jar_path.name,
            sha256=sha256,
            size_bytes=stat.st_size,
            last_modified=last_modified,
            launcher_name=location.launcher_name,
            instance_name=location.instance_name,
            archive_type=archive_type,
            non_standard_archive=archive_type == "java_archive_nonstandard_extension",
            instance_context=self._instance_context(location, None),
        )

        self.log("SCAN", f"Opening jar: {jar_path.name} ({human_size(result.size_bytes)})")
        self._scan_filename(result)
        self._apply_known_hashes(result)

        try:
            with zipfile.ZipFile(jar_path) as zf:
                infos = zf.infolist()
                if len(infos) > MAX_JAR_ENTRIES:
                    result.truncated = True
                    infos = infos[:MAX_JAR_ENTRIES]
                analyze_zip_structure(zf, result)
                analyze_signature_integrity(zf, result)
                self.log("JAR", "Reading manifest and metadata...")
                self._scan_metadata(zf, result)
                self._apply_allowlist(result)
                self.log("JAR", "Extracting class paths...")
                self._scan_entries(zf, self._prioritized_infos(infos, result), result)
        except zipfile.BadZipFile:
            result.error = "Unreadable jar: invalid or corrupted ZIP/JAR."
        except PermissionError as exc:
            result.error = f"Permission denied while reading jar: {exc}"
        except OSError as exc:
            result.error = f"Unable to read jar: {exc}"

        self.log("RULE", "Matching indicators...")
        self._apply_heuristics(result)
        self._scan_nested_archives_from_path(jar_path, location, result)
        analyze_mixin_annotations(result)
        analyze_class_graph(result)
        self._finalize_analysis_summary(result)
        self.log("SCORE", "Calculating risk...")
        breakdown = calculate_jar_risk(result)
        result.risk_score = breakdown.score
        result.verdict = breakdown.verdict
        result.risk_reasons = breakdown.reasons
        if self.cache:
            self.cache.put(result)
            self.cache.save()
        return result

    def deep_audit(self, jar_path: Path, result: JarScanResult) -> JarScanResult:
        """Stream every archive entry in an independent integrity and structure pass.

        This deliberately runs outside the normal prioritized class scan.  It catches
        truncated reads, malformed class payloads, encrypted entries, path traversal
        names and nested archives even when the normal scan stopped at a class budget.
        """
        entry_hashes: set[str] = set()
        duplicate_count = 0
        total_bytes = 0
        high_compression = 0
        embedded_native = 0
        class_entries = 0
        valid_class_entries = 0
        invalid_class_entries = 0
        nested_archives = 0
        encrypted_entries = 0
        suspicious_paths = 0
        max_compression_ratio = 0.0
        high_entropy_entries = 0
        max_entropy = 0.0
        feature_hits: list[str] = []
        with zipfile.ZipFile(jar_path) as zf:
            infos = zf.infolist()
            result.deep_audit_entries = len(infos)
            native_suffixes = (".dll", ".exe", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs")
            for info in infos:
                if info.is_dir():
                    continue
                normalized_name = info.filename.replace("\\", "/")
                lower_name = normalized_name.lower()
                if info.flag_bits & 0x1:
                    encrypted_entries += 1
                if normalized_name.startswith(("/", "\\")) or "../" in normalized_name or "\\..\\" in info.filename or "\x00" in info.filename:
                    suspicious_paths += 1
                if is_nested_archive_name(normalized_name):
                    nested_archives += 1
                if lower_name.endswith(".class"):
                    class_entries += 1
                if info.file_size and info.compress_size:
                    ratio = info.file_size / max(1, info.compress_size)
                    max_compression_ratio = max(max_compression_ratio, ratio)
                if lower_name.endswith(native_suffixes):
                    embedded_native += 1
                digest = hashlib.sha256()
                prefix = b""
                marker_tail = b""
                entropy_sample = bytearray()
                entry_base = normalized_name.rsplit("/", 1)[-1]
                entropy_candidate = (
                    lower_name.endswith((".class", ".bin", ".dat", ".kotlin_module"))
                    or (info.file_size >= OPAQUE_RESOURCE_MIN_BYTES and "." not in entry_base)
                )
                with zf.open(info, "r") as stream:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        if len(prefix) < 4:
                            prefix += chunk[: 4 - len(prefix)]
                        digest.update(chunk)
                        total_bytes += len(chunk)
                        if len(entropy_sample) < DEEP_AUDIT_SAMPLE_BYTES and entropy_candidate:
                            entropy_sample.extend(chunk[: DEEP_AUDIT_SAMPLE_BYTES - len(entropy_sample)])
                        if len(feature_hits) < 100 and _deep_audit_signal_entry(normalized_name):
                            window = (marker_tail + chunk).lower()
                            normalized_window = window.replace(b"\x00", b"")
                            for marker, _severity in DEEP_AUDIT_FEATURE_MARKERS:
                                marker_bytes = marker.encode("ascii")
                                if marker_bytes in normalized_window:
                                    entry_hit = f"{marker} @ {normalized_name}"
                                    if entry_hit not in feature_hits:
                                        feature_hits.append(entry_hit)
                            marker_tail = window[-128:]
                if lower_name.endswith(".class"):
                    if prefix == b"\xca\xfe\xba\xbe":
                        valid_class_entries += 1
                    else:
                        invalid_class_entries += 1
                if entropy_sample:
                    entropy = _shannon_entropy(bytes(entropy_sample))
                    max_entropy = max(max_entropy, entropy)
                    if entropy_candidate and entropy >= 7.4:
                        high_entropy_entries += 1
                value = digest.hexdigest()
                if value in entry_hashes:
                    duplicate_count += 1
                entry_hashes.add(value)
                if info.compress_size and info.file_size / max(1, info.compress_size) >= 100:
                    high_compression += 1
            result.deep_audit_crc_error = zf.testzip() or ""
        result.deep_audit_bytes = total_bytes
        result.deep_audit_sha256 = hashlib.sha256("".join(sorted(entry_hashes)).encode("ascii")).hexdigest()
        result.deep_audit_high_compression_entries = high_compression
        result.deep_audit_duplicate_hashes = duplicate_count
        result.deep_audit_embedded_native = embedded_native
        result.deep_audit_class_entries = class_entries
        result.deep_audit_valid_class_entries = valid_class_entries
        result.deep_audit_invalid_class_entries = invalid_class_entries
        result.deep_audit_nested_archives = nested_archives
        result.deep_audit_encrypted_entries = encrypted_entries
        result.deep_audit_suspicious_paths = suspicious_paths
        result.deep_audit_max_compression_ratio = round(max_compression_ratio, 2)
        result.deep_audit_high_entropy_entries = high_entropy_entries
        result.deep_audit_max_entropy = round(max_entropy, 3)
        result.deep_audit_feature_hits = feature_hits[:100]
        for anomaly in (
            f"{high_compression} high-compression archive entries" if high_compression else "",
            f"{duplicate_count} duplicate payload entries" if duplicate_count else "",
            f"{embedded_native} embedded executable/script entries" if embedded_native else "",
            f"CRC error in {result.deep_audit_crc_error}" if result.deep_audit_crc_error else "",
            f"{invalid_class_entries} class entries have an invalid CAFEBABE header" if invalid_class_entries else "",
            f"{encrypted_entries} encrypted archive entries" if encrypted_entries else "",
            f"{suspicious_paths} suspicious archive path(s)" if suspicious_paths else "",
            f"{high_entropy_entries} high-entropy code/data entries" if high_entropy_entries else "",
        ):
            if anomaly and anomaly not in result.zip_anomalies:
                result.zip_anomalies.append(anomaly)
        for hit in feature_hits[:20]:
            marker, _, entry_name = hit.partition(" @ ")
            configured = next((level for name, level in DEEP_AUDIT_FEATURE_MARKERS if name == marker), "low")
            severity = _deep_audit_marker_severity(marker, entry_name, configured)
            self._add_detection(
                result,
                rule_id="DEEP_AUDIT_FEATURE_STRING",
                rule_name="Deep audit feature string",
                category="Deep Audit",
                severity=severity,
                confidence=0.72 if severity == "high" else 0.35,
                matched_keyword=marker,
                source_type="deep_audit",
                evidence_preview=f"{entry_name}: {marker}",
                explanation="A restricted-feature identifier was found in an executable/configuration archive entry during the independent deep audit; documentation and localization files are excluded to reduce false flags.",
                context_type="deep_archive_content",
            )
        breakdown = calculate_jar_risk(result)
        result.risk_score = breakdown.score
        result.verdict = breakdown.verdict
        result.risk_reasons = breakdown.reasons
        self.log("AUDIT", f"Integrity pass: {len(infos)} entries, {human_size(total_bytes)} streamed, {class_entries} classes validated")
        return result

    def scan_bytes(
        self,
        archive_bytes: bytes,
        display_name: str,
        location: LauncherLocation,
        parent: JarScanResult,
        nested_path: str,
        depth: int,
    ) -> JarScanResult:
        digest = __import__("hashlib").sha256(archive_bytes).hexdigest()
        result = JarScanResult(
            path=parent.path,
            file_name=Path(display_name).name,
            sha256=digest,
            size_bytes=len(archive_bytes),
            last_modified=parent.last_modified,
            launcher_name=location.launcher_name,
            instance_name=location.instance_name,
            archive_type="nested_java_archive",
            nested_parent=str(parent.path),
            nested_path=nested_path,
            instance_context=parent.instance_context,
        )
        self._scan_filename(result)
        self._apply_known_hashes(result)
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                infos = zf.infolist()
                if len(infos) > MAX_JAR_ENTRIES:
                    result.truncated = True
                    infos = infos[:MAX_JAR_ENTRIES]
                analyze_zip_structure(zf, result)
                analyze_signature_integrity(zf, result)
                self._scan_metadata(zf, result)
                self._apply_allowlist(result)
                self._scan_entries(zf, self._prioritized_infos(infos, result), result)
                if depth < MAX_NESTED_DEPTH:
                    self._scan_nested_archives(zf, location, result, depth + 1)
        except zipfile.BadZipFile:
            result.error = "Unreadable nested jar: invalid or corrupted ZIP/JAR."
        except (OSError, RuntimeError) as exc:
            result.error = f"Unable to read nested jar: {exc}"
        self._apply_heuristics(result)
        analyze_mixin_annotations(result)
        analyze_class_graph(result)
        self._finalize_analysis_summary(result)
        breakdown = calculate_jar_risk(result)
        result.risk_score = breakdown.score
        result.verdict = breakdown.verdict
        result.risk_reasons = breakdown.reasons
        return result

    def _scan_filename(self, result: JarScanResult) -> None:
        self._scan_text(result, result.file_name, "filename", result.file_name)
        if is_randomish_name(result.file_name):
            self._add_detection(
                result,
                rule_id="RANDOM_LOOKING_FILENAME",
                rule_name="Random-looking filename",
                category="Heuristic",
                severity="low",
                confidence=0.35,
                matched_keyword="filename pattern",
                source_type="heuristic",
                evidence_preview=result.file_name,
                explanation="Jar filename looks random or heavily obfuscated.",
            )

    def _scan_metadata(self, zf: zipfile.ZipFile, result: JarScanResult) -> None:
        names = {info.filename.replace("\\", "/") for info in zf.infolist()}
        result.meta_inf_count = sum(1 for name in names if name.lower().startswith("meta-inf/"))
        result.manifest_found = "META-INF/MANIFEST.MF" in names
        for metadata_name in METADATA_FILES:
            if metadata_name not in names:
                continue
            try:
                info = zf.getinfo(metadata_name)
                if info.file_size > 512 * 1024:
                    continue
                data = zf.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile, KeyError):
                continue
            text = data.decode("utf-8", errors="replace")
            result.metadata_files_found.append(metadata_name)
            self._parse_metadata_text(result, metadata_name, text)
            for safe_text in self._safe_metadata_texts(metadata_name, text):
                self._scan_text(result, safe_text, "manifest", metadata_name, context_type="metadata")

    def _scan_entries(self, zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], result: JarScanResult) -> None:
        bytes_scanned = 0
        short_class_count = 0
        config_files_scanned = 0
        all_names = [info.filename.replace("\\", "/") for info in infos]
        self._analyze_tree_structure(result, all_names)
        for info in infos:
            name = info.filename.replace("\\", "/")
            lower = name.lower()
            if not lower.endswith(".class"):
                self._scan_opaque_resource(zf, info, result)
                if MIXIN_FILE_RE.search(lower):
                    self._scan_mixin_file(zf, info, result)
                    result.resources_analyzed_count += 1
                    continue
                if lower.endswith(".accesswidener"):
                    self._scan_access_widener(zf, info, result)
                    result.resources_analyzed_count += 1
                    continue
                if lower.startswith(SERVICE_PREFIX):
                    self._scan_service_entry(zf, info, result)
                    result.resources_analyzed_count += 1
                    continue
                if LANG_FILE_RE.search(lower):
                    self._scan_translation_file(zf, info, result)
                    result.resources_analyzed_count += 1
                    continue
                if self._is_build_metadata(lower):
                    self._scan_build_metadata(zf, info, result)
                    result.resources_analyzed_count += 1
                    continue
                self._scan_resource_path(result, name)
                if any(marker in lower for marker in ("/mixins", "accesswidener", "coremod", "launchplugin")):
                    self._scan_text(result, name, "class_path", name, context_type="package_path")
                if (
                    config_files_scanned < MAX_CONFIG_FILES_PER_JAR
                    and self._is_config_candidate(lower)
                    and lower not in METADATA_FILES_LOWER
                ):
                    self._scan_config_file(zf, info, result)
                    config_files_scanned += 1
                continue

            result.class_count += 1
            class_base = lower.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            if len(class_base) <= 2:
                short_class_count += 1
            result.suspicious_package_hits += self._package_context_score(lower)
            self._scan_text(result, lower, "class_path", name, context_type="package_path")

            if info.file_size > MAX_SINGLE_CLASS_BYTES:
                result.truncated = True
                continue
            if bytes_scanned >= MAX_CLASS_BYTES_PER_JAR:
                result.truncated = True
                continue
            try:
                data = zf.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            bytes_scanned += len(data)
            constants = parse_class_constants(data)
            attributes = parse_class_attributes(data)
            if attributes.parsed:
                result.parsed_attributes_count += attributes.attribute_count
            activity_score = opcode_activity_score(data)
            if activity_score:
                result.bytecode_activity_score = max(result.bytecode_activity_score, activity_score)
            if constants.parsed:
                strings = constants.utf8
                self._scan_bytecode_signals(result, constants.utf8, name)
            else:
                strings = extract_printable_strings(data, min_length=4)
            bytecode = analyze_class_bytecode(data)
            if bytecode.parsed:
                self._scan_bytecode_behavior(result, bytecode, name)
            self._record_class_analysis(result, name, constants, bytecode, strings, attributes, activity_score)
            result.string_count += len(strings)
            result.classes_analyzed_count += 1
            if strings:
                self._scan_strings_batch(result, strings, name)

        result.short_class_count = short_class_count
        if result.class_count:
            result.obfuscation_ratio = round(short_class_count / result.class_count, 3)
        self._apply_post_entry_contexts(result)
        self.log("CLASS", f"{result.class_count} class files indexed")
        self.log("STRINGS", f"{result.string_count} readable constants extracted")

    def _scan_opaque_resource(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, result: JarScanResult) -> None:
        """Inventory extensionless payloads without treating ordinary resources as malicious.

        Concealed loaders often store encrypted or packed class material under names
        such as ``pkg/a`` rather than ``*.class``/``*.jar``.  Entropy and zero-fill
        measurements are retained as support evidence; a verdict is only produced
        later when the same archive also contains active loader/native behaviour.
        """
        if info.is_dir() or info.file_size < OPAQUE_RESOURCE_MIN_BYTES:
            return
        normalized = info.filename.replace("\\", "/").strip("/")
        lower = normalized.lower()
        base = normalized.rsplit("/", 1)[-1]
        if not base or "." in base:
            return
        if lower.startswith("meta-inf/") or lower.startswith(("assets/", "data/")):
            return
        if base.lower() in {"license", "notice", "readme", "changelog"}:
            return
        try:
            with zf.open(info, "r") as stream:
                sample = stream.read(OPAQUE_RESOURCE_SAMPLE_BYTES)
        except (OSError, RuntimeError, zipfile.BadZipFile, KeyError):
            return
        if not sample:
            return
        entropy = _shannon_entropy(sample)
        zero_ratio = sample.count(0) / len(sample)
        high_entropy = entropy >= 7.6
        zero_filled = zero_ratio >= 0.98 and info.file_size >= 512 * 1024
        payload_format = _opaque_payload_format(sample)
        if not high_entropy and not zero_filled and not payload_format:
            return
        if normalized not in result.opaque_payload_paths:
            result.opaque_payload_paths.append(normalized)
            result.opaque_payload_bytes += info.file_size
            if high_entropy:
                result.opaque_payload_high_entropy += 1
            if zero_filled:
                result.opaque_payload_zero_filled += 1
        if payload_format:
            result.opaque_payload_formats[normalized] = payload_format
            severity = "critical" if payload_format == "PE executable" else "high"
            self._add_detection(
                result,
                rule_id="HIDDEN_EXECUTABLE_RESOURCE",
                rule_name="Executable payload hidden without an extension",
                category="Concealment",
                severity=severity,
                confidence=0.96 if severity == "critical" else 0.9,
                matched_keyword=payload_format,
                source_type="resource",
                evidence_preview=f"{normalized}: extensionless {payload_format}, {info.file_size} bytes",
                explanation="An extensionless archive resource contains a recognizable executable/class/archive header. This bypasses ordinary suffix-based nested-content inspection and is treated as active payload evidence.",
                context_type="hidden_executable_resource",
            )

    def _scan_nested_archives_from_path(self, jar_path: Path, location: LauncherLocation, result: JarScanResult) -> None:
        try:
            with zipfile.ZipFile(jar_path) as zf:
                self._scan_nested_archives(zf, location, result, depth=1)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return

    def _scan_nested_archives(
        self,
        zf: zipfile.ZipFile,
        location: LauncherLocation,
        parent: JarScanResult,
        depth: int,
    ) -> None:
        if depth > MAX_NESTED_DEPTH or len(parent.nested_results) >= MAX_NESTED_JARS:
            return
        for info in zf.infolist():
            if len(parent.nested_results) >= MAX_NESTED_JARS:
                return
            name = info.filename.replace("\\", "/")
            if not is_nested_archive_name(name) or info.file_size > 64 * 1024 * 1024:
                continue
            try:
                data = zf.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            if not data.startswith(b"PK"):
                continue
            child = self.scan_bytes(data, name, location, parent, nested_path=name, depth=depth)
            parent.nested_results.append(child)
            material_nested_rules = {
                item.rule_id
                for item in child.detections
                if item.rule_id in STRONG_BYTECODE_BEHAVIOR_RULES
                or item.rule_id in {"KNOWN_CLIENT_NAME_EXACT", "CLIENT_KNOWN_HACK_CLIENT", "CLIENT_SELF_DESTRUCT", "LOCAL_HASH_KNOWN_BLOCKED", "COMBAT_KILLAURA", "COMBO_KILLAURA_BEHAVIOR"}
            }
            if child.verdict in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"} and material_nested_rules:
                self._add_detection(
                    parent,
                    rule_id="NESTED_SUSPICIOUS_ARCHIVE",
                    rule_name="Suspicious nested jar",
                    category="Nested Archive",
                    severity="high" if child.verdict in {"HIGH_RISK", "CRITICAL"} else "medium",
                    confidence=0.82,
                    matched_keyword=name,
                    source_type="nested",
                    evidence_preview=f"Nested: {name} | {child.verdict} {child.risk_score}/100",
                    explanation="Suspicious indicators were found inside an embedded jar.",
                    context_type="nested_archive",
                )

    def _scan_text(
        self,
        result: JarScanResult,
        text: str,
        source_type: str,
        evidence: str,
        context_type: str | None = None,
    ) -> None:
        if not text:
            return
        self._record_tokens(result, text, source_type)
        text_index = prepare_text(text)
        context = context_type or self._classify_text_context(text, evidence)
        for rule in self.rules:
            for keyword in rule.keywords:
                if keyword_matches_index(keyword, text_index):
                    if not self._accept_keyword_context(keyword, source_type, text, rule):
                        continue
                    confidence = self._confidence_for_source(rule, source_type, context)
                    self._add_detection(
                        result,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=confidence,
                        matched_keyword=keyword,
                        source_type=source_type,
                        evidence_preview=evidence,
                        explanation=rule.description + (f" Note: {rule.false_positive_note}" if rule.false_positive_note else ""),
                        context_type=context,
                    )
        if source_type in {"string", "config", "translation"}:
            self._scan_decoded_variants(result, text, source_type, evidence, context)

    def _scan_strings_batch(self, result: JarScanResult, strings: list[str], class_name: str) -> None:
        combined = "\nXIEN_STRING_BOUNDARY\n".join(strings)
        self._record_tokens(result, combined, "string")
        text_index = prepare_text(combined)
        for rule in self.rules:
            for keyword in rule.keywords:
                if not keyword_matches_index(keyword, text_index):
                    continue
                evidence = self._first_string_evidence(strings, keyword)
                if not evidence:
                    continue
                if not self._accept_keyword_context(keyword, "string", evidence, rule):
                    continue
                context = self._classify_text_context(evidence, class_name)
                confidence = self._confidence_for_source(rule, "string", context)
                self._add_detection(
                    result,
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=confidence,
                    matched_keyword=keyword,
                    source_type="string",
                    evidence_preview=evidence,
                    explanation=rule.description + (f" Note: {rule.false_positive_note}" if rule.false_positive_note else ""),
                    context_type=context,
                )
                self._scan_gui_context(result, keyword, evidence, class_name)
                self._scan_decoded_variants(result, evidence, "string", class_name, context)

    def _scan_decoded_variants(
        self,
        result: JarScanResult,
        text: str,
        source_type: str,
        evidence: str,
        original_context: str,
    ) -> None:
        for variant in decoded_variants(text):
            if variant == text:
                continue
            variant_index = prepare_text(variant)
            for rule in self.rules:
                if rule.severity not in {"medium", "high", "critical"} or rule.rule_id in {"CLIENT_ANTICHEAT_REFERENCE", "CLIENT_INJECTION_REFERENCE"}:
                    continue
                for keyword in rule.keywords:
                    if not keyword_matches_index(keyword, variant_index):
                        continue
                    if not self._accept_keyword_context(keyword, source_type, variant, rule):
                        continue
                    result.decoded_string_hits.append(f"{keyword}: {variant[:80]}")
                    self._add_detection(
                        result,
                        rule_id="DECODED_STRING_FEATURE_CONTEXT",
                        rule_name="Decoded string feature context",
                        category="String",
                        severity="medium",
                        confidence=0.58,
                        matched_keyword=keyword,
                        source_type=source_type,
                        evidence_preview=f"{evidence}: decoded {variant[:120]}",
                        explanation="A simple decoded string variant contains a feature indicator.",
                        context_type=f"decoded_{original_context or 'string'}",
                    )
                    break

    def _is_config_candidate(self, lower_path: str) -> bool:
        if not lower_path.endswith(CONFIG_SUFFIXES):
            return False
        if any(marker in lower_path for marker in ASSET_DATA_PATH_MARKERS):
            return False
        return any(hint in lower_path for hint in CONFIG_PATH_HINTS)

    def _scan_config_file(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, result: JarScanResult) -> None:
        if info.file_size > MAX_CONFIG_BYTES:
            return
        try:
            text = zf.read(info).decode("utf-8", errors="replace")
        except (OSError, RuntimeError, zipfile.BadZipFile, UnicodeError):
            return
        if not text.strip():
            return
        result.resources_analyzed_count += 1
        self._scan_text(result, text, "config", info.filename, context_type="config_key")
        analyze_numeric_context(result, info.filename, text, extract_numbers_from_text(text))

    def _scan_mixin_file(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, result: JarScanResult) -> None:
        text = self._read_small_text(zf, info)
        if text is None:
            return
        result.mixin_files_found.append(info.filename)
        self._scan_text(result, text, "mixin", info.filename, context_type="mixin_config")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        package_name = str(data.get("package") or "").strip()
        for meta_key in ("injectors", "compatibilityLevel", "refmap", "required"):
            value = data.get(meta_key)
            if value:
                self._scan_text(result, f"{meta_key}: {value}", "mixin", info.filename, context_type="mixin_config")
        mixin_names = []
        for key in ("mixins", "client", "server"):
            value = data.get(key)
            if isinstance(value, list):
                mixin_names.extend(str(item) for item in value if isinstance(item, str))
        for mixin_name in mixin_names:
            full_name = mixin_name if "." in mixin_name or not package_name else f"{package_name}.{mixin_name}"
            normalized = self._normalize_class_name(full_name)
            result.mixin_classes.add(normalized)
            self._scan_text(result, full_name, "mixin", info.filename, context_type="class_like")
        result.client_side = result.client_side or bool(data.get("client")) or str(data.get("environment", "")).lower() == "client"

    def _scan_access_widener(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, result: JarScanResult) -> None:
        text = self._read_small_text(zf, info)
        if text is None:
            return
        result.access_widener_files_found.append(info.filename)
        self._scan_text(result, text, "access_widener", info.filename, context_type="class_like")
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("accessWidener"):
                continue
            compact = "".join(tokens_for_text(stripped))
            if any(target in compact for target in MIXIN_TARGET_TOKENS):
                result.access_widener_targets.add(stripped)

    def _scan_service_entry(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, result: JarScanResult) -> None:
        text = self._read_small_text(zf, info, max_bytes=64 * 1024)
        if text is None:
            return
        result.service_entries_found.append(info.filename)
        for line in text.splitlines():
            class_name = line.strip()
            if not class_name or class_name.startswith("#"):
                continue
            result.entrypoint_classes.add(self._normalize_class_name(class_name))
            self._scan_text(result, class_name, "service", info.filename, context_type="class_like")

    def _scan_translation_file(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, result: JarScanResult) -> None:
        text = self._read_small_text(zf, info)
        if text is None:
            return
        pairs: list[tuple[str, str]] = []
        if info.filename.lower().endswith(".json"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict):
                pairs.extend((str(key), str(value)) for key, value in data.items())
        else:
            for line in text.splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    key, value = line.split("=", 1)
                    pairs.append((key.strip(), value.strip()))
        for key, value in pairs[:300]:
            combined = f"{key}: {value}"
            self._scan_text(result, combined, "translation", info.filename, context_type="translation_key")
            tokens = set(tokens_for_text(combined))
            if tokens.intersection(FEATURE_CONTEXT_TOKENS) and tokens.intersection(GUI_SETTING_TOKENS | MODULE_MANAGER_TOKENS):
                self._add_detection(
                    result,
                    rule_id="TRANSLATION_FEATURE_CONTEXT",
                    rule_name="Translation feature context",
                    category="Config",
                    severity="medium",
                    confidence=0.72,
                    matched_keyword="translation feature setting",
                    source_type="translation",
                    evidence_preview=combined,
                    explanation="Translation keys or labels expose module/setting names for a suspicious feature.",
                    context_type="translation_key",
                )

    def _is_build_metadata(self, lower_path: str) -> bool:
        return any(marker in lower_path for marker in BUILD_METADATA_MARKERS)

    def _scan_build_metadata(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, result: JarScanResult) -> None:
        text = self._read_small_text(zf, info, max_bytes=512 * 1024)
        if text is None:
            return
        lower_name = info.filename.lower()
        self._scan_text(result, text[:4000], "metadata", info.filename, context_type="metadata")
        if lower_name.endswith("pom.properties") or lower_name.endswith("gradle.properties"):
            for line in text.splitlines():
                if "=" not in line or line.lstrip().startswith("#"):
                    continue
                key, value = [part.strip() for part in line.split("=", 1)]
                if key in {"groupId", "artifactId", "version", "mod_id", "archives_base_name"}:
                    result.build_metadata[key] = value
                    if key == "version":
                        result.maven_version = result.maven_version or value
        elif lower_name.endswith("pom.xml"):
            for key in ("groupId", "artifactId", "version", "name"):
                match = re.search(rf"<{key}>\s*([^<]+)\s*</{key}>", text, re.IGNORECASE)
                if match:
                    result.build_metadata[key] = match.group(1).strip()
                    if key == "version":
                        result.maven_version = result.maven_version or result.build_metadata[key]
        else:
            for key in ("author", "license", "description"):
                match = re.search(rf"{key}\s*[:=]\s*([^\r\n]+)", text, re.IGNORECASE)
                if match:
                    result.build_metadata[key] = match.group(1).strip()[:120]
            impl_match = re.search(r"implementation[-_. ]version\s*[:=]\s*([^\r\n]+)", text, re.IGNORECASE)
            if impl_match:
                result.implementation_version = result.implementation_version or impl_match.group(1).strip()[:80]

    def _scan_resource_path(self, result: JarScanResult, path: str) -> None:
        lower = path.lower()
        if not any(marker in lower for marker in ("assets/", "textures/", "gui", "screen", "module", "category", "setting", "icon", "shader")):
            return
        tokens = set(tokens_for_text(path))
        if tokens.intersection(FEATURE_CONTEXT_TOKENS | GUI_SETTING_TOKENS | MODULE_MANAGER_TOKENS):
            self._add_detection(
                result,
                rule_id="RESOURCE_SEMANTIC_CONTEXT",
                rule_name="Resource semantic context",
                category="Resource",
                severity="medium",
                confidence=0.62,
                matched_keyword="resource feature path",
                source_type="resource",
                evidence_preview=path,
                explanation="Resource path names expose module, GUI, category, or setting semantics tied to feature indicators.",
                context_type="resource_path",
            )

    def _read_small_text(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, max_bytes: int = MAX_CONFIG_BYTES) -> str | None:
        if info.file_size > max_bytes:
            return None
        try:
            return zf.read(info).decode("utf-8", errors="replace")
        except (OSError, RuntimeError, zipfile.BadZipFile, UnicodeError):
            return None

    def _scan_bytecode_signals(self, result: JarScanResult, constants: list[str], class_name: str) -> None:
        method_hits: list[str] = []
        api_hits: list[str] = []
        for value in constants:
            compact = "".join(tokens_for_text(value))
            if compact in METHOD_FIELD_SIGNALS or any(signal in compact for signal in METHOD_FIELD_SIGNALS):
                method_hits.append(value)
            if compact in MINECRAFT_API_MARKERS or any(marker in compact for marker in MINECRAFT_API_MARKERS):
                api_hits.append(value)

        for value in method_hits[:3]:
            self._add_detection(
                result,
                rule_id="BYTECODE_METHOD_FIELD_SIGNAL",
                rule_name="Suspicious method/field naming",
                category="Bytecode",
                severity="low",
                confidence=0.35,
                matched_keyword=value,
                source_type="string",
                evidence_preview=f"{class_name}: constant_pool contains {value}",
                explanation="A method or field name often seen in client modules was found. This is weak alone and stronger with feature matches.",
                context_type="method_like",
            )
        if api_hits:
            self._record_tokens(result, " ".join(api_hits), "string")

    def _scan_bytecode_behavior(self, result: JarScanResult, analysis: BytecodeAnalysis, class_name: str) -> None:
        refs = analysis.method_refs + analysis.field_refs + analysis.class_refs + analysis.string_literals + analysis.method_names
        joined = "\n".join(refs)
        self._record_tokens(result, joined, "string")
        lowered = [value.lower() for value in refs]

        # Record decoder behaviour separately from verdict rules.  Crypto,
        # Base64 and XOR helpers are common in legitimate libraries, so the
        # signal is intentionally only a review hint unless it is paired with
        # an actual concealed feature hit elsewhere in the jar.
        decoder_signals: list[str] = []
        if self._contains_ref(lowered, (
            "javax/crypto/cipher.getinstance",
            "javax.crypto.cipher.getinstance",
            "cipher.getinstance",
            "secretkeyspec",
            "cipher.dofinal",
        )):
            decoder_signals.append("JVM crypto decoder")
        if self._contains_ref(lowered, (
            "java/util/base64",
            "java.util.base64",
            "base64$decoder",
            "base64.getdecoder",
            "base64.decode",
        )):
            decoder_signals.append("Base64 decoder")
        if self._contains_ref(lowered, (
            "xor",
            "xordecode",
            "xor_decode",
            "decryptstring",
            "decrypt_string",
            "decipher",
            "decodekey",
            "decode_key",
        )):
            decoder_signals.append("XOR/string decoder")
        for signal in decoder_signals:
            if signal not in result.decoder_signals:
                result.decoder_signals.append(signal)

        cipher_decrypt = self._contains_ref(lowered, ("javax/crypto/cipher.dofinal", "cipher.dofinal"))
        jar_stream = self._contains_ref(lowered, ("java/util/jar/jarinputstream", "getnextjarentry"))
        defines_class = self._contains_ref(lowered, ("defineclass(", ".defineclass"))
        custom_loader = self._contains_ref(lowered, ("java/lang/classloader", "findclass", "loadclass"))
        resource_stream = self._contains_ref(lowered, ("getresourceasstream", "class.getresourceasstream"))
        opaque_resource_literal = any(
            value.startswith("/") and Path(value).suffix == "" and len(value.rsplit("/", 1)[-1]) >= 1
            for value in analysis.string_literals
        )
        if defines_class and custom_loader and (resource_stream or opaque_resource_literal):
            self._add_detection(
                result,
                rule_id="BYTECODE_DIRECT_CLASS_DEFINITION",
                rule_name="Direct resource-backed class definition",
                category="Concealment",
                severity="high",
                confidence=0.91,
                matched_keyword="opaque resource path + ClassLoader.defineClass",
                source_type="opcode",
                evidence_preview=f"{class_name}: maps extensionless bundled payload paths and defines JVM classes directly",
                explanation="The class is a custom loader that turns non-class resources into live JVM classes. This can be legitimate alone, so it becomes decisive only when correlated with opaque payload and native-loader evidence.",
                context_type="resource_payload_loader",
            )

        jna_library = self._contains_ref(lowered, (
            "com/sun/jna/nativelibrary", "nativelibrary.getinstance", "nativelibrary.getfunction",
        ))
        jna_memory = self._contains_ref(lowered, (
            "com/sun/jna/pointer", "com/sun/jna/memory", "pointer.read", "pointer.write", "invokepointer",
        ))
        process_or_native_load = self._contains_ref(lowered, (
            "java/lang/runtime.exec", "runtime.exec", "java/lang/processbuilder", "processbuilder.start", "system.load",
        ))
        if jna_library and jna_memory and process_or_native_load:
            self._add_detection(
                result,
                rule_id="BYTECODE_NATIVE_MEMORY_LOADER_BRIDGE",
                rule_name="Native memory/process loader bridge",
                category="Loader",
                severity="critical",
                confidence=0.96,
                matched_keyword="JNA NativeLibrary + Pointer/Memory + process/native load",
                source_type="opcode",
                evidence_preview=f"{class_name}: resolves native functions, reads/writes native memory, and launches or loads native code",
                explanation="A single class combines JNA function resolution, raw pointer/memory access, and process/native loading. This is strong active loader behaviour rather than a name-only match.",
                context_type="native_memory_loader",
            )

        raw_socket_channel = self._contains_ref(lowered, ("java/nio/channels/socketchannel", "socketchannel.open", "socketchannel.connect"))
        random_access_file = self._contains_ref(lowered, ("java/io/randomaccessfile", "randomaccessfile.read", "randomaccessfile.write"))
        if raw_socket_channel and random_access_file and resource_stream:
            self._add_detection(
                result,
                rule_id="BYTECODE_RAW_CHANNEL_PAYLOAD_IO",
                rule_name="Raw channel and payload file I/O",
                category="Loader",
                severity="high",
                confidence=0.88,
                matched_keyword="SocketChannel + RandomAccessFile + bundled resource",
                source_type="opcode",
                evidence_preview=f"{class_name}: combines raw socket channels, random-access files, and bundled resource reads",
                explanation="The class can transfer or rewrite opaque bundled data through low-level network and file channels. This supports a concealed payload-loader finding when correlated with the loader classes.",
                context_type="payload_transport",
            )
        if cipher_decrypt and jar_stream and defines_class and custom_loader:
            self._add_detection(
                result,
                rule_id="BYTECODE_ENCRYPTED_JAR_LOADER",
                rule_name="Encrypted in-memory JAR class loader",
                category="Concealment",
                severity="critical",
                confidence=0.98,
                matched_keyword="Cipher.doFinal + JarInputStream + defineClass",
                source_type="heuristic",
                evidence_preview=f"{class_name}: decrypts an archive, reads JAR entries, and defines classes directly in memory",
                explanation="The class decrypts a hidden JAR payload and loads its classes directly into the JVM. The concealed payload bypasses normal static class inspection.",
                context_type="encrypted_payload_loader",
            )

        remote_request = self._contains_ref(lowered, ("java/net/http/httpclient.send", "httpclient.send", "urlconnection.getinputstream"))
        byte_payload = self._contains_ref(lowered, ("bodyhandlers.ofbytearray", "httpresponse.body", "base64$decoder.decode"))
        target_loader = self._contains_ref(lowered, ("gettargetclassloader", "fabriclauncherbase.getlauncher", ".loadclass"))
        reflection_exec = self._contains_ref(lowered, ("constructor.newinstance", "method.invoke", "getdeclaredconstructor"))
        if remote_request and byte_payload and target_loader and reflection_exec:
            self._add_detection(
                result,
                rule_id="BYTECODE_REMOTE_PAYLOAD_LOADER",
                rule_name="Remote encrypted payload execution",
                category="Loader",
                severity="critical",
                confidence=0.98,
                matched_keyword="HTTP byte payload + target ClassLoader + reflection",
                source_type="heuristic",
                evidence_preview=f"{class_name}: downloads bytes, attaches to Fabric target ClassLoader, and invokes the loaded entrypoint",
                explanation="The mod downloads executable class payload bytes and runs them through the game ClassLoader using reflection. The executed code is not present as normal visible classes in the JAR.",
                context_type="remote_payload_loader",
            )

        hardware_id = self._contains_ref(lowered, ("queryuuid", "queryserialnumber", "identifyingnumber", "biosserial", "dmidecode.queryuuid", "iokitutil"))
        fingerprint_hash = self._contains_ref(lowered, ("messagedigest.getinstance", "messagedigest.digest"))
        if remote_request and fingerprint_hash and target_loader:
            self._add_detection(
                result,
                rule_id="BYTECODE_HWID_REMOTE_LOADER",
                rule_name="Hardware-bound remote loader",
                category="Loader",
                severity="high",
                confidence=0.92,
                matched_keyword="hardware fingerprint hash + remote payload loader",
                source_type="heuristic",
                evidence_preview=f"{class_name}: hashes platform identity data before remote class loading",
                explanation="The loader builds a device fingerprint and uses it in a remote payload-loading flow, a pattern commonly used by licensed private clients.",
                context_type="hardware_bound_loader",
            )

        attack_entity = self._contains_ref(lowered, ("class_636.method_2918", "attackentity", "attack_entity", "hio.a(lddm;lcgk;)v"))
        swing_hand = self._contains_ref(lowered, ("method_6104", "swinghand", "swing_hand", "chl.a(lcdb;)v"))
        target_entity = self._contains_ref(lowered, ("field_1692", "crosshair", "targetedentity", "entityhitresult", "method_76762", "class_3966", "lftk;", "ftk"))
        cooldown_gate = self._contains_ref(lowered, ("method_7261", "attackcooldown", "cooldownprogress", "ddm.i(f)f"))
        random_gate = self._contains_ref(lowered, ("java/lang/math.random", "java/util/random", "threadlocalrandom"))
        weapon_gate = self._contains_ref(lowered, ("class_1829", "class_1743", "sworditem", "axeitem"))
        client_tick_or_input = self._contains_ref(lowered, ("oninput", "onstarttick", "ontick", "clienttickevents", "minecraftclient", "class_310"))

        branch_gate = analysis.conditional_branches >= 2
        same_method_chain = any(self._method_has_triggerbot_chain(method) for method in analysis.methods)

        if same_method_chain or (attack_entity and swing_hand and cooldown_gate and (target_entity or weapon_gate or client_tick_or_input) and branch_gate):
            details = ["attackEntity", "swingHand", "cooldown gate"]
            if target_entity:
                details.append("target entity")
            if weapon_gate:
                details.append("weapon gate")
            if random_gate:
                details.append("randomized delay")
            if branch_gate:
                details.append(f"{analysis.conditional_branches} conditional branches")
            if same_method_chain:
                details.append("same-method behavior chain")
            self._add_detection(
                result,
                rule_id="BYTECODE_TBOT_AUTOMATION",
                rule_name="Bytecode combat automation behavior",
                category="Combat",
                severity="critical",
                confidence=0.94,
                matched_keyword="attackEntity + swingHand + cooldown",
                source_type="heuristic",
                evidence_preview=f"{class_name}: {' + '.join(details)}",
                explanation="Bytecode invokes player attack and hand swing behind cooldown/target checks, which matches triggerbot-style automation even when names are hidden.",
            )

        hurt_time = self._contains_ref(lowered, ("field_6235", "hurttime", "hurt_time"))
        jump_call = self._contains_ref(lowered, ("method_6043", ".jump", "jump()"))
        on_ground = self._contains_ref(lowered, ("method_24828", "isonground", "on_ground"))
        if hurt_time and jump_call and on_ground and client_tick_or_input:
            self._add_detection(
                result,
                rule_id="BYTECODE_JUMPRESET_BEHAVIOR",
                rule_name="Bytecode JumpReset behavior",
                category="Combat",
                severity="high",
                confidence=0.88,
                matched_keyword="hurtTime + onGround + jump",
                source_type="heuristic",
                evidence_preview=f"{class_name}: hurtTime + onGround + jump call in tick/input flow",
                explanation="Bytecode checks hurt timing/on-ground state and calls jump, which matches jump-reset behavior even when names are hidden.",
            )

        behavior_checks = (
            ("BYTECODE_AIMASSIST_BEHAVIOR", "Bytecode AimAssist behavior", "AimAssist", "high", 0.88, self._method_has_aimassist_behavior, "target angle calculation + yaw/pitch adjustment", "A method calculates target angles and applies conditional yaw/pitch adjustments, matching aim-assist behavior."),
            ("BYTECODE_REACH_BEHAVIOR", "Bytecode Reach behavior", "Reach", "high", 0.86, self._method_has_reach_behavior, "entity distance + extended raycast threshold", "A method combines entity-distance logic, raycast shape, and an extended interaction threshold, matching Reach behavior."),
            ("BYTECODE_VELOCITY_BEHAVIOR", "Bytecode Velocity behavior", "Velocity", "high", 0.87, self._method_has_velocity_behavior, "velocity packet + motion scaling", "A method reads velocity/knockback data and conditionally scales player motion, matching Velocity modification."),
            ("BYTECODE_AUTOCLICKER_BEHAVIOR", "Bytecode AutoClicker behavior", "AutoClicker", "high", 0.89, self._method_has_autoclicker_behavior, "clock/random delay + repeated click", "A method combines timing/random delay logic with repeated mouse/attack calls, matching AutoClicker behavior."),
        )
        for rule_id, rule_name, category, severity, confidence, predicate, evidence, explanation in behavior_checks:
            matched_method = next((method for method in analysis.methods if predicate(method)), None)
            if matched_method is None:
                continue
            if not self._behavior_context_allows(rule_id, class_name, matched_method):
                continue
            self._add_detection(
                result,
                rule_id=rule_id,
                rule_name=rule_name,
                category=category,
                severity=severity,
                confidence=confidence,
                matched_keyword=evidence,
                source_type="heuristic",
                evidence_preview=f"{class_name}#{matched_method.name}: {evidence}; branches={matched_method.conditional_branches}",
                explanation=explanation,
                context_type="bytecode_behavior",
            )

        for method in analysis.methods:
            self._scan_self_destruct_method(result, method, class_name)

    def _behavior_context_allows(self, rule_id: str, class_name: str, method) -> bool:
        """Reject mapping-neutral shapes when their semantic owner is clearly non-combat.

        Neutral JVM signatures are useful against obfuscation, but a renderer can
        naturally have triple-float setters, integer getters and many branches.
        In an explicit render/config/GUI class we therefore require named/mapped
        behavior APIs instead of promoting the generic descriptor shape alone.
        """
        context = f"{class_name} {method.name}".lower()
        non_combat_context = any(token in context for token in (
            "render", "renderer", "cull", "frustum", "config", "screen", "widget", "menu", "cloth",
        ))
        if not non_combat_context:
            return True
        refs = [value.lower() for value in method.method_refs + method.field_refs + method.class_refs + method.string_literals]
        if rule_id == "BYTECODE_VELOCITY_BEHAVIOR":
            packet = self._contains_ref(refs, ("entityvelocityupdates2cpacket", "explosions2cpacket", "velocitypacket", "class_2743", "class_2664"))
            motion = self._contains_ref(refs, ("setvelocity", "addvelocity", "velocityx", "velocityy", "velocityz", "motionx", "motiony", "motionz"))
            return packet and motion
        if rule_id == "BYTECODE_AIMASSIST_BEHAVIOR":
            rotation = self._contains_ref(refs, ("setyaw", "setpitch", "rotationyaw", "rotationpitch", "field_6031", "field_5965"))
            target = self._contains_ref(refs, ("targetedentity", "entityhitresult", "livingentity", "playerentity", "class_1309", "class_1657"))
            return rotation and target
        if rule_id == "BYTECODE_REACH_BEHAVIOR":
            distance = self._contains_ref(refs, ("distanceto", "squareddistanceto", "getdistance", "method_5739", "method_5858"))
            raycast = self._contains_ref(refs, ("raycast", "entityhitresult", "projectileutil", "method_17744", "method_18075"))
            return distance and raycast
        if rule_id == "BYTECODE_AUTOCLICKER_BEHAVIOR":
            return self._contains_ref(refs, ("doattack", "clickmouse", "onmousebutton", "glfwgetmousebutton", "method_1536"))
        return True

    def _scan_self_destruct_method(self, result: JarScanResult, method, class_name: str) -> None:
        refs = [value.lower() for value in method.method_refs + method.field_refs + method.class_refs + method.string_literals]
        own_location = self._contains_ref(refs, ("getprotectiondomain", "getcodesource", "getlocation", "getclassloader", "protectiondomain"))
        deletes_file = self._contains_ref(refs, ("java/io/file.delete", "java/nio/file/files.delete", "deleteifexists", "deleteonexit"))
        overwrites_file = self._contains_ref(refs, ("fileoutputstream.<init>", "java/nio/file/files.write", "randomaccessfile.setlength", "truncateexisting"))
        moves_file = self._contains_ref(refs, ("java/nio/file/files.move", "replaceexisting", "atomicmove"))
        remote_read = self._contains_ref(refs, ("java/net/url.openstream", "openstream()ljava/io/inputstream", "httpclient.send", "urlconnection.getinputstream"))
        preserves_time = self._contains_ref(refs, ("setlastmodified", "setlastmodifiedtime", "lastmodified"))
        shutdown_hook = self._contains_ref(refs, ("runtime.addshutdownhook", "addshutdownhook"))
        process_exec = self._contains_ref(refs, ("java/lang/processbuilder", "runtime.exec", "processbuilder.start"))
        command_text = " ".join(value.lower() for value in method.string_literals)
        delete_command = process_exec and any(token in command_text for token in ("powershell", "cmd.exe", "remove-item", " del ", "erase ", "start-process"))
        self_destruct_text = any(token in command_text for token in ("selfdestruct", "self destruct", "uninstall client", "delete client", "cleanup traces"))

        if own_location and delete_command:
            self._add_detection(
                result, "BYTECODE_SELF_DESTRUCT_COMMAND", "External-command self destruct", "Concealment", "critical", 0.96,
                "own JAR location + ProcessBuilder/Runtime.exec deletion", "heuristic",
                f"{class_name}#{method.name}: resolves its own code location and launches a deletion command",
                "The method resolves its own running JAR and invokes an operating-system deletion command, strongly matching self-destruct behavior.", "self_destruct",
            )
        if own_location and deletes_file:
            self._add_detection(
                result, "BYTECODE_SELF_DELETE", "Own JAR deletion behavior", "Concealment", "critical", 0.95,
                "own JAR location + delete/deleteOnExit", "heuristic",
                f"{class_name}#{method.name}: ProtectionDomain/CodeSource + file deletion",
                "The method resolves its own JAR location and deletes it directly or schedules it for deletion.", "self_destruct",
            )
        if own_location and shutdown_hook and (deletes_file or delete_command):
            self._add_detection(
                result, "BYTECODE_SELF_DESTRUCT_SHUTDOWN", "Shutdown-hook cleanup behavior", "Concealment", "high", 0.92,
                "shutdown hook + own-file cleanup", "heuristic",
                f"{class_name}#{method.name}: shutdown hook tied to own-file deletion",
                "Cleanup is registered for JVM shutdown and targets the running JAR, a common self-destruct pattern.", "self_destruct",
            )
        if own_location and remote_read and (overwrites_file or moves_file):
            details = "remote replacement + own JAR overwrite"
            if preserves_time:
                details += " + timestamp restoration"
            self._add_detection(
                result, "BYTECODE_SELF_RESTORE_OVERWRITE", "Remote clean-copy self restore", "Concealment", "critical", 0.95,
                details, "heuristic", f"{class_name}#{method.name}: {details}",
                "The method downloads replacement content and overwrites or replaces its own JAR; timestamp restoration further indicates concealment.", "self_destruct",
            )
        if self_destruct_text and own_location and (overwrites_file or moves_file):
            self._add_detection(
                result, "BYTECODE_SELF_RESTORE_OVERWRITE", "Self-destruct overwrite behavior", "Concealment", "high", 0.9,
                "self-destruct text + own JAR replacement", "heuristic", f"{class_name}#{method.name}: explicit self-destruct text and own-file replacement",
                "Explicit self-destruct language is tied to replacement or truncation of the running JAR.", "self_destruct",
            )

    def _method_has_triggerbot_chain(self, method) -> bool:
        refs = [
            value.lower()
            for value in method.method_refs + method.field_refs + method.class_refs + method.string_literals
        ]
        attack = self._contains_ref(refs, ("class_636.method_2918", "attackentity", "attack_entity", "hio.a(lddm;lcgk;)v"))
        swing = self._contains_ref(refs, ("method_6104", "swinghand", "swing_hand", "chl.a(lcdb;)v"))
        cooldown = self._contains_ref(refs, ("method_7261", "attackcooldown", "cooldownprogress", "ddm.i(f)f"))
        target = self._contains_ref(refs, ("crosshair", "targetedentity", "entityhitresult", "method_76762", "class_3966", "lftk;", "ftk"))
        mapped_chain = attack and swing and cooldown and target and method.conditional_branches >= 2
        return mapped_chain or self._version_neutral_triggerbot_chain(method)

    def _method_has_aimassist_behavior(self, method) -> bool:
        refs = [value.lower() for value in method.method_refs + method.field_refs + method.class_refs + method.string_literals]
        angle_math = self._contains_ref(refs, ("java/lang/math.atan2", "atan2", "wrapdegrees", "method_15393"))
        rotation_write = self._contains_ref(refs, ("setyaw", "setpitch", "field_6031", "field_5965", "rotationyaw", "rotationpitch"))
        target = self._contains_ref(refs, ("targetedentity", "entityhitresult", "livingentity", "playerentity", "class_1309", "class_1657"))
        parsed = [item for item in (self._parse_method_ref(value) for value in method.method_refs) if item]
        float_setters = [item for item in parsed if item[2] == ["F"] and item[3] == "V"]
        object_fields = [value for value in method.field_refs if re.search(r"L[^;]+;$", value)]
        neutral_shape = angle_math and len(float_setters) >= 2 and bool(object_fields)
        return angle_math and (rotation_write or neutral_shape) and (target or object_fields) and method.conditional_branches >= 2

    def _method_has_reach_behavior(self, method) -> bool:
        refs = [value.lower() for value in method.method_refs + method.field_refs + method.class_refs + method.string_literals]
        distance = self._contains_ref(refs, ("distanceto", "squareddistanceto", "getdistance", "method_5739", "method_5858"))
        raycast = self._contains_ref(refs, ("raycast", "entityhitresult", "box.raycast", "projectileutil", "method_17744", "method_18075"))
        threshold = any(3.01 <= abs(value) <= 7.0 for value in method.numeric_constants)
        if distance and raycast and threshold and method.conditional_branches >= 1:
            return True
        parsed = [item for item in (self._parse_method_ref(value) for value in method.method_refs) if item]
        distance_shape = any(len(item[2]) == 1 and item[2][0].startswith("L") and item[3] in {"D", "F"} for item in parsed)
        raycast_shape = any(len(item[2]) >= 2 and sum(arg in {"D", "F", "Z"} for arg in item[2]) >= 2 and item[3].startswith("L") for item in parsed)
        object_fields = any(re.search(r"L[^;]+;$", value) for value in method.field_refs)
        return distance_shape and raycast_shape and object_fields and threshold and method.conditional_branches >= 2

    def _method_has_velocity_behavior(self, method) -> bool:
        refs = [value.lower() for value in method.method_refs + method.field_refs + method.class_refs + method.string_literals]
        packet = self._contains_ref(refs, ("entityvelocityupdates2cpacket", "explosions2cpacket", "velocitypacket", "class_2743", "class_2664"))
        motion = self._contains_ref(refs, ("setvelocity", "addvelocity", "multiply", "velocityx", "velocityy", "velocityz", "motionx", "motiony", "motionz"))
        scale = any(0.0 <= abs(value) < 1.0 and abs(value) not in {0.0} for value in method.numeric_constants)
        if packet and motion and scale and method.conditional_branches >= 1:
            return True
        parsed = [item for item in (self._parse_method_ref(value) for value in method.method_refs) if item]
        motion_owners = {item[0] for item in parsed if item[2] in (["D", "D", "D"], ["F", "F", "F"]) and item[3] == "V"}
        read_owners = [item[0] for item in parsed if not item[2] and item[3] in {"I", "S"}]
        packet_owner = next((owner for owner in set(read_owners) if read_owners.count(owner) >= 3), "")
        packet_field = bool(packet_owner) and any(f"L{packet_owner};" in value for value in method.field_refs)
        return bool(motion_owners) and packet_field and packet_owner not in motion_owners and scale and method.conditional_branches >= 2

    def _method_has_autoclicker_behavior(self, method) -> bool:
        refs = [value.lower() for value in method.method_refs + method.field_refs + method.class_refs + method.string_literals]
        clock = self._contains_ref(refs, ("system.currenttimemillis", "system.nanotime", "currenttimemillis", "nanotime"))
        random_delay = self._contains_ref(refs, ("java/util/random", "threadlocalrandom", "math.random", "nextint", "nextdouble"))
        click = self._contains_ref(refs, ("doattack", "clickmouse", "onmousebutton", "mousebutton", "glfwgetmousebutton", "method_1536"))
        cps_constant = any(4.0 <= abs(value) <= 30.0 for value in method.numeric_constants)
        repeated_flow = method.backward_branches >= 1 or method.conditional_branches >= 2
        return clock and click and repeated_flow and (random_delay or cps_constant)

    def _version_neutral_triggerbot_chain(self, method) -> bool:
        """Match the stable JVM call shape without relying on Minecraft names/mappings."""
        parsed = [self._parse_method_ref(value) for value in method.method_refs]
        parsed = [value for value in parsed if value is not None]
        attacks = [value for value in parsed if len(value[2]) == 2 and value[3] == "V" and all(arg.startswith("L") for arg in value[2])]
        if not attacks:
            return False
        one_object_void = [value for value in parsed if len(value[2]) == 1 and value[2][0].startswith("L") and value[3] == "V"]
        float_gates = [value for value in parsed if value[2] == ["F"] and value[3] == "F"]
        object_fields = [value for value in method.field_refs if re.search(r"L[^;]+;$", value)]
        if not one_object_void or not float_gates or not object_fields or method.conditional_branches < 3:
            return False
        for _attack_owner, _attack_name, args, _return_type in attacks:
            player_type = args[0][1:-1]
            if any(owner == player_type for owner, _name, _args, _ret in float_gates):
                return True
        return False

    def _parse_method_ref(self, value: str):
        match = re.match(r"^(.+)\.([^.(]+)\((.*)\)(.+)$", value)
        if not match:
            return None
        owner, name, descriptor_args, return_type = match.groups()
        args = re.findall(r"L[^;]+;|\[[A-Z]|[ZBCSIJFD]", descriptor_args)
        return owner, name, args, return_type

    def _record_class_analysis(
        self,
        result: JarScanResult,
        class_name: str,
        constants,
        bytecode: BytecodeAnalysis,
        strings: list[str],
        attributes: ClassAttributeSummary,
        activity_score: int,
    ) -> None:
        normalized = self._normalize_class_name(class_name)
        refs = set()
        descriptors = set()
        attribute_strings: list[str] = []
        if constants.parsed:
            refs.update(self._normalize_class_name(value) for value in constants.class_refs if value)
            descriptors.update(constants.descriptors)
            record_annotation_context(result, normalized, constants.utf8)
        if attributes.parsed:
            if attributes.major_version:
                result.class_version_counts[attributes.major_version] = result.class_version_counts.get(attributes.major_version, 0) + 1
            if attributes.source_file:
                result.source_files[normalized] = attributes.source_file
                attribute_strings.append(attributes.source_file)
            if attributes.local_variables:
                result.local_variable_names[normalized] = set(attributes.local_variables)
                attribute_strings.extend(sorted(attributes.local_variables)[:80])
            if attributes.inner_classes:
                result.inner_class_names[normalized] = set(attributes.inner_classes)
                attribute_strings.extend(sorted(attributes.inner_classes)[:80])
            if attributes.annotations:
                result.annotation_refs[normalized] = set(attributes.annotations)
                attribute_strings.extend(sorted(attributes.annotations)[:80])
                record_annotation_context(result, normalized, list(attributes.annotations))
            if attributes.bootstrap_refs:
                result.bootstrap_refs[normalized] = set(attributes.bootstrap_refs)
                attribute_strings.extend(sorted(attributes.bootstrap_refs)[:80])
            descriptors.update(attributes.descriptors)
        if bytecode.parsed:
            refs.update(self._normalize_class_name(value.split(".", 1)[0]) for value in bytecode.class_refs if value)
            refs.update(self._normalize_class_name(value.split(".", 1)[0]) for value in bytecode.method_refs if value)
            refs.update(self._normalize_class_name(value.split(".", 1)[0]) for value in bytecode.field_refs if value)
        refs.discard("")
        if refs:
            result.class_references[normalized] = refs

        descriptor_counts = descriptor_contexts(descriptors, self.mapping_hints)
        result.entity_descriptor_refs += descriptor_counts["entity_descriptor_refs"]
        result.player_descriptor_refs += descriptor_counts["player_descriptor_refs"]
        result.render_descriptor_refs += descriptor_counts["render_descriptor_refs"]
        result.input_descriptor_refs += descriptor_counts["input_descriptor_refs"]
        result.network_descriptor_refs += descriptor_counts["network_descriptor_refs"]

        mapping_contexts = self.mapping_hints.contexts_for_text(" ".join([class_name, *strings[:150], *refs, *descriptors, *attribute_strings]))
        text = " ".join([class_name, *strings[:150], *refs, *mapping_contexts, *attribute_strings])
        feature_tokens = self._feature_tokens(text)
        api_refs = self._api_tokens(" ".join([*refs, *descriptors, *mapping_contexts, *attribute_strings]))
        if feature_tokens:
            result.class_feature_tokens[normalized] = feature_tokens
        if api_refs:
            result.class_api_refs[normalized] = api_refs
            if "minecraftclient" in api_refs:
                result.client_side = True
        if attributes.parsed and feature_tokens:
            self._scan_attribute_feature_context(result, normalized, attributes, feature_tokens)
        if feature_tokens and any(descriptor_counts.values()):
            self._add_detection(
                result,
                rule_id="DESCRIPTOR_FEATURE_CONTEXT",
                rule_name="Descriptor feature context",
                category="Bytecode",
                severity="medium",
                confidence=0.64,
                matched_keyword=", ".join(sorted(feature_tokens)[:3]),
                source_type="descriptor",
                evidence_preview=f"{class_name}: descriptors reference entity/player/render/input/network context",
                explanation="Method/field descriptors reference Minecraft client contexts near feature tokens.",
                context_type="descriptor_context",
            )
        if feature_tokens and activity_score >= 48:
            self._add_detection(
                result,
                rule_id="ACTIVE_BYTECODE_FEATURE_CONTEXT",
                rule_name="Active bytecode feature context",
                category="Bytecode",
                severity="medium",
                confidence=0.62,
                matched_keyword=", ".join(sorted(feature_tokens)[:3]),
                source_type="opcode",
                evidence_preview=f"{class_name}: bytecode_activity_score={activity_score}",
                explanation="Opcode shape suggests active logic near a feature-looking class rather than a data-only artifact.",
                context_type="opcode_shape",
            )
        numbers = list(attributes.numeric_constants)
        numbers.extend(extract_numbers_from_text(" ".join(strings[:120])))
        analyze_numeric_context(result, normalized, text, numbers)

        role = classify_class_role(normalized, refs | api_refs | mapping_contexts, [*strings[:100], *attribute_strings], set(attribute_strings))
        result.class_roles[normalized] = role
        if role == "SETTING_CLASS":
            result.setting_model_score = min(100, result.setting_model_score + 18)
        elif role == "CONFIG_SCREEN":
            result.gui_context_score = min(100, result.gui_context_score + 18)
        elif role in {"TICK_HANDLER", "RENDER_HANDLER", "INPUT_HANDLER", "PACKET_HANDLER", "MODULE_CLASS"}:
            result.module_system_score = min(100, result.module_system_score + 8)

        if normalized in result.entrypoint_classes:
            result.class_contexts.setdefault(normalized, set()).add("entrypoint")
        if normalized in result.mixin_classes or "mixin" in tokens_for_text(class_name):
            result.class_contexts.setdefault(normalized, set()).add("mixin")
            targets = api_refs.intersection(MIXIN_TARGET_TOKENS)
            if targets:
                result.mixin_targets.setdefault(normalized, set()).update(targets)
            if targets and feature_tokens:
                self._add_detection(
                    result,
                    rule_id="MIXIN_TARGET_FEATURE_CONTEXT",
                    rule_name="Mixin target feature context",
                    category="Mixin",
                    severity="high",
                    confidence=0.86,
                    matched_keyword=", ".join(sorted(feature_tokens)[:3]),
                    source_type="mixin",
                    evidence_preview=f"{class_name}: targets {', '.join(sorted(targets)[:3])}",
                    explanation="Mixin class feature naming is connected to sensitive Minecraft client/player/render targets.",
                    context_type="mixin_target",
                )

        if feature_tokens and len(api_refs.intersection(MIXIN_TARGET_TOKENS | MINECRAFT_API_MARKERS)) >= 3:
            self._add_detection(
                result,
                rule_id="CLASS_IMPORT_DENSITY",
                rule_name="Feature class client API density",
                category="Bytecode",
                severity="medium",
                confidence=0.7,
                matched_keyword=", ".join(sorted(feature_tokens)[:3]),
                source_type="graph",
                evidence_preview=f"{class_name}: client API refs {', '.join(sorted(api_refs)[:5])}",
                explanation="A combat/render/movement feature-looking class has dense Minecraft client API references.",
                context_type="class_graph",
            )
        self._score_module_system(result, class_name, [*strings, *attribute_strings])
        self._score_obfuscated_strings(result, strings)

    def _scan_attribute_feature_context(
        self,
        result: JarScanResult,
        class_name: str,
        attributes: ClassAttributeSummary,
        feature_tokens: set[str],
    ) -> None:
        feature = ", ".join(sorted(feature_tokens)[:3])
        if attributes.source_file and self._feature_tokens(attributes.source_file):
            self._add_detection(
                result,
                rule_id="SOURCEFILE_FEATURE_CONTEXT",
                rule_name="SourceFile feature context",
                category="Bytecode",
                severity="high" if class_name.split("/")[-1] in {"a", "b", "c"} else "medium",
                confidence=0.72,
                matched_keyword=feature,
                source_type="source_file_attribute",
                evidence_preview=f"{class_name}: SourceFile={attributes.source_file}",
                explanation="SourceFile debug metadata references a feature/module name, useful when class paths are obfuscated.",
                context_type="debug_attribute",
            )
        local_hits = [name for name in sorted(attributes.local_variables) if self._feature_tokens(name) or set(tokens_for_text(name)).intersection(GUI_SETTING_TOKENS)]
        if local_hits:
            self._add_detection(
                result,
                rule_id="LOCAL_VARIABLE_FEATURE_CONTEXT",
                rule_name="Debug local variable feature context",
                category="Bytecode",
                severity="medium",
                confidence=0.58,
                matched_keyword=feature,
                source_type="local_variable_table",
                evidence_preview=f"{class_name}: locals {', '.join(local_hits[:5])}",
                explanation="Debug local-variable names expose feature or setting context.",
                context_type="debug_attribute",
            )
        annotation_text = " ".join(attributes.annotations)
        annotation_tokens = set(tokens_for_text(annotation_text))
        if annotation_tokens.intersection({"eventhandler", "subscribeevent", "clientmodinitializer", "modinitializer", "inject", "redirect", "overwrite", "sideonly", "environment"}):
            self._add_detection(
                result,
                rule_id="ANNOTATION_EVENT_FEATURE_CONTEXT",
                rule_name="Annotation/event feature context",
                category="Bytecode",
                severity="medium",
                confidence=0.66,
                matched_keyword=feature,
                source_type="annotation_attribute",
                evidence_preview=f"{class_name}: annotations {', '.join(sorted(attributes.annotations)[:5])}",
                explanation="Annotation metadata ties feature-looking code to client entry, event, or mixin hooks.",
                context_type="annotation_context",
            )
        inner_hits = [name for name in sorted(attributes.inner_classes) if self._feature_tokens(name)]
        if inner_hits:
            self._add_detection(
                result,
                rule_id="INNER_CLASS_FEATURE_CONTEXT",
                rule_name="Inner class feature context",
                category="Bytecode",
                severity="medium",
                confidence=0.58,
                matched_keyword=feature,
                source_type="inner_class_attribute",
                evidence_preview=f"{class_name}: inner classes {', '.join(inner_hits[:5])}",
                explanation="InnerClasses metadata exposes feature/module naming.",
                context_type="debug_attribute",
            )

    def _record_tokens(self, result: JarScanResult, text: str, source_type: str) -> None:
        tokens = tokens_for_text(text)
        if not tokens:
            return
        token_values = set(tokens)
        token_values.update(ngrams(tokens, 2, 3))
        result.analysis_tokens.update(token_values)
        bucket = result.source_tokens.setdefault(source_type, set())
        bucket.update(token_values)

    def _first_string_evidence(self, strings: list[str], keyword: str) -> str | None:
        for value in strings:
            if keyword_matches(keyword, value):
                return value
        return None

    def _parse_metadata_text(self, result: JarScanResult, metadata_name: str, text: str) -> None:
        lower = metadata_name.lower()
        if lower.endswith(("fabric.mod.json", "quilt.mod.json")):
            result.loader_type = "Quilt" if "quilt" in lower else "Fabric"
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return
            if not isinstance(data, dict):
                return
            loader_data = data.get("quilt_loader") if isinstance(data.get("quilt_loader"), dict) else data
            if isinstance(loader_data, dict):
                result.mod_id = result.mod_id or str(loader_data.get("id") or "")
                result.mod_name = result.mod_name or str(loader_data.get("name") or "")
                version = loader_data.get("version")
                if version:
                    result.mod_version = result.mod_version or str(version)
                    result.metadata_version = result.metadata_version or str(version)
            env = str(data.get("environment") or "").lower()
            result.client_side = result.client_side or env == "client"
            entrypoints = data.get("entrypoints")
            if isinstance(entrypoints, dict):
                for key, value in entrypoints.items():
                    classes = self._flatten_metadata_value(value)
                    for class_name in classes:
                        result.entrypoint_classes.add(self._normalize_class_name(class_name))
                    if str(key).lower() == "client" and classes:
                        result.client_side = True
            for mixin in self._flatten_metadata_value(data.get("mixins")):
                if mixin:
                    result.mixin_files_found.append(mixin)
            access_widener = data.get("accessWidener") or data.get("access_widener")
            if isinstance(access_widener, str):
                result.access_widener_files_found.append(access_widener)
            self._collect_metadata_versions(result, data)
            collect_dependency_metadata(result, data)
            return

        if lower.endswith("mods.toml"):
            result.loader_type = "Forge"
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                data = {}
            mods = data.get("mods") if isinstance(data, dict) else None
            if isinstance(mods, list) and mods:
                first = mods[0]
                if isinstance(first, dict):
                    result.mod_id = result.mod_id or str(first.get("modId") or "")
                    result.mod_name = result.mod_name or str(first.get("displayName") or "")
                    version = first.get("version")
                    if version:
                        result.mod_version = result.mod_version or str(version)
                        result.metadata_version = result.metadata_version or str(version)
            self._collect_metadata_versions(result, data)
            collect_dependency_metadata(result, data)
            for value in re.findall(r"(?:client|setup|entrypoint|main)[A-Za-z0-9_.-]*\s*=\s*\"([^\"]+)\"", text, re.IGNORECASE):
                result.entrypoint_classes.add(self._normalize_class_name(value))
            return

        if lower.endswith("mcmod.info"):
            result.loader_type = "Forge"
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            items = data if isinstance(data, list) else [data]
            for item in items:
                if isinstance(item, dict):
                    result.mod_id = result.mod_id or str(item.get("modid") or item.get("modId") or "")
                    result.mod_name = result.mod_name or str(item.get("name") or "")
                    version = item.get("version")
                    if version:
                        result.mod_version = result.mod_version or str(version)
                        result.metadata_version = result.metadata_version or str(version)
                    self._collect_metadata_versions(result, item)
                    collect_dependency_metadata(result, item)
            return

        if lower.endswith("manifest.mf"):
            for line in text.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                if key in {"premain-class", "agent-class"} and value:
                    result.java_agent_manifest = True
                elif key == "can-retransform-classes" and value.lower() == "true":
                    result.java_agent_retransform = True
                elif key == "can-redefine-classes" and value.lower() == "true":
                    result.java_agent_redefine = True
                elif key == "can-set-native-method-prefix" and value.lower() == "true":
                    result.java_agent_native_prefix = True
                if key == "implementation-version":
                    result.implementation_version = result.implementation_version or value
                    result.metadata_version = result.metadata_version or value
                if key in {"main-class", "tweakclass", "fmlcoreplugin", "mixinconfigs"}:
                    for item in re.split(r"[,; ]+", value):
                        if item.endswith(".json"):
                            result.mixin_files_found.append(item)
                        elif "." in item:
                            result.entrypoint_classes.add(self._normalize_class_name(item))

    def _safe_metadata_texts(self, metadata_name: str, text: str) -> list[str]:
        lower = metadata_name.lower()
        if lower.endswith(".json"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return []
            values: list[str] = []
            if isinstance(data, dict):
                for key in ("id", "name", "version", "description"):
                    value = data.get(key)
                    if isinstance(value, str):
                        values.append(f"{metadata_name} {key}: {value}")
                for key in ("entrypoints", "mixins", "accessWidener", "access_widener"):
                    value = data.get(key)
                    values.extend(self._flatten_metadata_value(value))
                loader = data.get("quilt_loader")
                if isinstance(loader, dict):
                    for key in ("id", "version"):
                        value = loader.get(key)
                        if isinstance(value, str):
                            values.append(value)
                    metadata = loader.get("metadata")
                    if isinstance(metadata, dict) and isinstance(metadata.get("name"), str):
                        values.append(metadata["name"])
            return values
        if lower.endswith(".toml"):
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                data = {}
            values = []
            if isinstance(data, dict):
                mods = data.get("mods")
                if isinstance(mods, list):
                    for item in mods:
                        if isinstance(item, dict):
                            for key in ("modId", "displayName", "version"):
                                value = item.get(key)
                                if isinstance(value, str):
                                    values.append(value)
            if values:
                return values
            return re.findall(r'(?:modId|displayName|version)\s*=\s*"([^"]+)"', text)
        if lower.endswith("manifest.mf"):
            wanted = {
                "Implementation-Title",
                "Implementation-Version",
                "Specification-Title",
                "Main-Class",
                "MixinConfigs",
                "TweakClass",
            }
            values = []
            for line in text.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if key.strip() in wanted:
                    values.append(value.strip())
            return values
        return []

    def _flatten_metadata_value(self, value: object) -> list[str]:
        out: list[str] = []
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, list):
            for item in value:
                out.extend(self._flatten_metadata_value(item))
        elif isinstance(value, dict):
            for item in value.values():
                out.extend(self._flatten_metadata_value(item))
        return out[:40]

    def _contains_ref(self, refs: list[str], needles: tuple[str, ...]) -> bool:
        return any(any(needle in ref for needle in needles) for ref in refs)

    def _confidence_for_source(self, rule: Rule, source_type: str, context_type: str = "") -> float:
        source_weight = {
            "filename": 0.42,
            "manifest": 0.52,
            "metadata": 0.58,
            "class_path": 0.82,
            "config": 0.9,
            "translation": 0.86,
            "resource": 0.62,
            "mixin": 0.86,
            "access_widener": 0.72,
            "service": 0.76,
            "string": 0.88,
            "graph": 0.74,
            "hash": 0.98,
            "nested": 0.82,
            "correlation": 0.64,
            "heuristic": 0.62,
        }.get(source_type, 0.5)
        context_weight = {
            "config_key": 1.1,
            "translation_key": 1.08,
            "gui_label": 1.08,
            "method_like": 1.04,
            "class_like": 1.02,
            "package_path": 1.0,
            "log_message": 0.78,
            "random_text": 0.62,
        }.get(context_type, 1.0)
        return min(1.0, round(source_weight * context_weight * rule.confidence_weight, 2))

    def _accept_keyword_context(self, keyword: str, source_type: str, text: str, rule: Rule) -> bool:
        keyword_l = keyword.lower().strip()
        if keyword_l not in WEAK_CONTEXT_KEYWORDS:
            return True
        tokens = path_tokens(text)
        keyword_tokens = path_tokens(keyword_l)
        context_tokens = tokens - keyword_tokens
        if keyword_l in {"reach", "velocity"}:
            strong_feature_context = {"combat", "cheat", "clickgui", "exploit", "feature", "features", "ghost", "hack", "hacks", "module", "modules", "setting", "settings"}
            if source_type == "class_path":
                return bool(tokens.intersection(strong_feature_context))
            if source_type in {"string", "config", "translation"}:
                behavior_context = {"attack", "entity", "knockback", "packet", "range", "reducer", "setting", "toggle"}
                return bool(context_tokens.intersection(strong_feature_context | behavior_context))
            if source_type == "filename":
                return bool(tokens.intersection({"cheat", "client", "ghost", "hack", "module"}))
            return False
        if keyword_l == "phase":
            movement_context = {"movement", "exploit", "hack", "hacks", "noclip", "clip", "module", "modules"}
            if tokens.intersection({"render", "dragon", "phases"}):
                return False
            return source_type == "class_path" and bool(tokens.intersection(movement_context))
        if keyword_l == "spider":
            if tokens.intersection({"eye", "eyes"}):
                return False
            return source_type == "class_path" and bool(tokens.intersection({"movement", "exploit", "hack", "hacks", "module", "modules"}))
        if rule.rule_id in {"CLIENT_ANTICHEAT_REFERENCE", "CLIENT_INJECTION_REFERENCE"}:
            return source_type in {"filename", "class_path", "manifest"} and bool(tokens.intersection(MATCH_CONTEXT_TOKENS | {"mixin"}))
        if source_type in {"string", "config", "translation"}:
            return bool(context_tokens.intersection(MATCH_CONTEXT_TOKENS))
        if source_type == "class_path":
            return bool(tokens.intersection(MATCH_CONTEXT_TOKENS | HARD_PACKAGE_TOKENS | SOFT_PACKAGE_TOKENS))
        if source_type == "filename":
            return bool(tokens.intersection(MATCH_CONTEXT_TOKENS | {"hack", "client", "cheat"}))
        return True

    def _add_detection(
        self,
        result: JarScanResult,
        rule_id: str,
        rule_name: str,
        category: str,
        severity: str,
        confidence: float,
        matched_keyword: str,
        source_type: str,
        evidence_preview: str,
        explanation: str,
        context_type: str = "",
    ) -> None:
        key_count = 0
        clean_preview = self._clean_preview(evidence_preview)
        for item in result.detections:
            if item.rule_id == rule_id and item.source_type == source_type and item.matched_keyword.lower() == matched_keyword.lower():
                key_count += 1
                if item.evidence_preview == clean_preview:
                    return
        if key_count >= MAX_DETECTIONS_PER_RULE_SOURCE:
            return
        location_class, location_method = self._detection_location(clean_preview)
        result.detections.append(
            DetectionMatch(
                rule_id=rule_id,
                rule_name=rule_name,
                category=category,
                severity=severity,
                confidence=confidence,
                matched_keyword=matched_keyword,
                source_type=source_type,
                evidence_preview=clean_preview,
                explanation=explanation,
                context_type=context_type,
                class_name=location_class,
                method_name=location_method,
            )
        )
        if severity in {"critical", "high", "medium"}:
            result.strong_evidence_count += 1
        else:
            result.weak_evidence_count += 1

    @staticmethod
    def _detection_location(evidence: str) -> tuple[str, str]:
        """Extract class/method coordinates when bytecode evidence includes them."""
        match = re.search(r"(?:^|\s)([A-Za-z_$][\w$/$.-]*)#([A-Za-z_$<>][\w$<>.-]*)", evidence)
        if match:
            return match.group(1).replace("/", "."), match.group(2)
        class_match = re.search(r"(?:^|\s)([A-Za-z_$][\w$/$.-]*(?:\.class)?)", evidence)
        return (class_match.group(1).replace("/", ".").removesuffix(".class"), "") if class_match else ("", "")

    def _apply_heuristics(self, result: JarScanResult) -> None:
        self._apply_combination_heuristics(result)
        self._apply_package_role_heuristics(result)
        self._apply_tree_heuristics(result)
        self._apply_loader_context_heuristics(result)
        self._apply_graph_heuristics(result)
        self._apply_module_system_heuristics(result)
        self._apply_build_metadata_heuristics(result)
        content_high = [
            item
            for item in result.detections
            if item.source_type in {"class_path", "string", "manifest", "config", "translation", "mixin", "graph"}
            and item.severity in {"high", "critical"}
            and item.rule_id != "CLIENT_ANTICHEAT_REFERENCE"
        ]
        if is_safe_looking_name(result.file_name) and content_high:
            result.renamed_suspicious = True
            names = ", ".join(sorted({item.rule_name for item in content_high})[:4])
            self._add_detection(
                result,
                rule_id="RENAMED_SUSPICIOUS_JAR",
                rule_name="Possible renamed suspicious jar",
                category="Heuristic",
                severity="high",
                confidence=0.85,
                matched_keyword="safe-looking filename + suspicious internals",
                source_type="heuristic",
                evidence_preview=f"{result.file_name}: {names}",
                explanation="The filename looks like a normal utility/performance mod, but internal class paths or strings contain high-risk indicators.",
            )
        if result.class_count >= 40 and result.obfuscation_ratio >= 0.45:
            self._add_detection(
                result,
                rule_id="OBFUSCATED_RANDOM_CLASSES",
                rule_name="High short-class density",
                category="Heuristic",
                severity="medium",
                confidence=0.65,
                matched_keyword="short class names",
                source_type="heuristic",
                evidence_preview=f"{result.short_class_count}/{result.class_count} class names are 1-2 chars",
                explanation="The jar has many very short class names. This can be normal obfuscation, but should be reviewed with other findings.",
            )
        if result.suspicious_package_hits >= 14 and content_high:
            self._add_detection(
                result,
                rule_id="SUSPICIOUS_PACKAGE_CONTEXT",
                rule_name="Suspicious package context",
                category="Heuristic",
                severity="medium",
                confidence=0.6,
                matched_keyword="combat/module/client package context",
                source_type="heuristic",
                evidence_preview=f"{result.suspicious_package_hits} suspicious package context hits",
                explanation="Suspicious package names appear repeatedly near other content indicators.",
            )
        if result.java_agent_manifest:
            capabilities = [
                name
                for enabled, name in (
                    (result.java_agent_retransform, "class retransformation"),
                    (result.java_agent_redefine, "class redefinition"),
                    (result.java_agent_native_prefix, "native method prefixing"),
                )
                if enabled
            ]
            # A Java agent is not automatically malicious.  Raise it for review
            # only when the agent also has strong concealment characteristics.
            concealed_agent = result.class_count >= 8 and result.obfuscation_ratio >= 0.65
            self._add_detection(
                result,
                rule_id="OBFUSCATED_JAVA_AGENT" if concealed_agent else "JAVA_AGENT_CAPABILITY",
                rule_name="Obfuscated Java instrumentation agent" if concealed_agent else "Java instrumentation agent",
                category="Runtime Instrumentation",
                severity="high" if concealed_agent else "low",
                confidence=0.86 if concealed_agent else 0.48,
                matched_keyword="Premain-Class/Agent-Class",
                source_type="manifest",
                evidence_preview=(
                    "agent entrypoint present"
                    + (f"; capabilities: {', '.join(capabilities)}" if capabilities else "")
                    + f"; short-class ratio={result.obfuscation_ratio:.0%}"
                ),
                explanation=(
                    "The manifest declares a Java instrumentation agent and the implementation is heavily obfuscated. "
                    "Agents with retransformation/redefinition capabilities can alter classes at runtime."
                    if concealed_agent
                    else "The manifest declares a Java instrumentation agent. This is a review signal, not a standalone cheat verdict."
                ),
                context_type="java_agent",
            )
        if result.decoder_signals:
            result.obfuscated_string_score = min(
                100,
                result.obfuscated_string_score + min(30, len(result.decoder_signals) * 10),
            )
            feature_context = bool(result.decoded_string_hits) or (
                result.obfuscation_ratio >= 0.25
                and bool(result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS))
            )
            self._add_detection(
                result,
                rule_id="OBFUSCATED_DECODER_BEHAVIOR",
                rule_name="Obfuscated string decoder behavior",
                category="Concealment",
                severity="medium" if feature_context else "low",
                confidence=0.72 if feature_context else 0.38,
                matched_keyword=" + ".join(result.decoder_signals),
                source_type="opcode",
                evidence_preview=(
                    "; ".join(result.decoder_signals)
                    + ("; decoded feature text matched" if result.decoded_string_hits else "")
                ),
                explanation=(
                    "The bytecode contains a decoder used alongside concealed feature text. "
                    "The decoded content is included in the verdict evidence."
                    if feature_context
                    else "The bytecode contains a crypto/Base64/XOR-style decoder. This is common in libraries and is only a low-confidence review signal by itself."
                ),
                context_type="obfuscated_decoder",
            )

    def _apply_combination_heuristics(self, result: JarScanResult) -> None:
        tokens = result.analysis_tokens
        if not tokens:
            return

        class_tokens = result.source_tokens.get("class_path", set())
        string_tokens = result.source_tokens.get("string", set())
        combos = [
            (
                "COMBO_TRIGGERBOT_BEHAVIOR",
                "TriggerBot behavior combo",
                "Combat",
                "critical",
                0.9,
                self._has_any(class_tokens | string_tokens, {"triggerbot", "trigger bot"})
                and self._has_any(tokens, {"attack", "entity", "tick", "mouse", "click", "client tick events"}),
                "trigger/click + attack/entity/tick",
            ),
            (
                "COMBO_KILLAURA_BEHAVIOR",
                "KillAura behavior combo",
                "Combat",
                "critical",
                0.9,
                self._has_any(tokens, {"killaura", "kill aura"}) or self._has_all(tokens, {"kill", "aura"}),
                "kill aura feature tokens",
            ),
            (
                "COMBO_REACH_BEHAVIOR",
                "Reach behavior combo",
                "Combat",
                "high",
                0.82,
                (self._has_any(class_tokens, {"reach"}) or self._has_any(string_tokens, {"reachdistance", "reach distance", "attackrange", "attack range"}))
                and self._has_any(tokens, {"entityhitresult", "entity hit result", "raycast", "attack", "entity"}),
                "reach/range + entity hit/raycast/attack",
            ),
            (
                "COMBO_VELOCITY_BEHAVIOR",
                "Velocity behavior combo",
                "Combat",
                "high",
                0.78,
                (self._has_any(tokens, {"antikb", "anti knockback", "knockback"}) and self._has_any(tokens, {"packet", "player", "client connection"}))
                or (self._has_any(class_tokens, {"velocity"}) and self._has_any(tokens, {"packet", "player", "client connection"}))
                or (self._has_any(string_tokens, {"velocitymode", "velocity mode"}) and self._has_any(tokens, {"packet", "player"})),
                "velocity/knockback + packet/player",
            ),
            (
                "COMBO_ESP_RENDER",
                "ESP render combo",
                "Render",
                "high",
                0.8,
                (self._has_any(class_tokens, {"esp", "playeresp", "chestesp", "storageesp", "wallhack"})
                 or self._has_any(string_tokens, {"playeresp", "player esp", "chestesp", "chest esp", "storageesp", "storage esp", "wallhack"}))
                and self._has_any(tokens, {"render", "world", "player", "hud", "world render events", "hud render callback"}),
                "esp/tracer/nametag + render/player/world",
            ),
            (
                "COMBO_XRAY_RENDER",
                "XRay render combo",
                "Render",
                "high",
                0.76,
                self._has_any(tokens, {"xray", "x ray", "oreesp", "ore esp"})
                and self._has_any(tokens, {"render", "block", "world"}),
                "xray/ore + render/block/world",
            ),
            (
                "COMBO_AUTOCLICKER_BEHAVIOR",
                "AutoClicker behavior combo",
                "Combat",
                "high",
                0.82,
                (self._has_any(tokens, {"autoclicker", "auto clicker"}) or (self._has_any(tokens, {"clicker"}) and self._has_any(tokens, {"cps", "mincps", "maxcps"})))
                and self._has_any(tokens, {"mouse", "click", "tick", "keybinding"}),
                "clicker/cps + mouse/click/tick",
            ),
            (
                "COMBO_HURTCAM_MANIPULATION",
                "HurtCam manipulation combo",
                "Combat Visual",
                "low",
                0.45,
                self._has_any(tokens, {"betterhurtcam", "better hurt cam", "hurtcam", "hurt cam", "nohurtcam", "no hurt cam"})
                and self._has_any(tokens, {"disable", "disablehurtcam", "change", "changehurtcamtype", "multiplier", "tilt", "tiltviewwhenhurt", "damage", "yaw", "getdamagetiltyaw", "rotation"})
                and self._has_any(tokens, {"gamerenderer", "game renderer", "minecraftclient", "minecraft client", "keybinding", "tick", "render"}),
                "hurtcam + disable/change/multiplier + client/render hook",
            ),
        ]

        for rule_id, name, category, severity, confidence, matched, evidence in combos:
            if not matched:
                continue
            self._add_detection(
                result,
                rule_id=rule_id,
                rule_name=name,
                category=category,
                severity=severity,
                confidence=confidence,
                matched_keyword=evidence,
                source_type="heuristic",
                evidence_preview=f"combined tokens: {evidence}",
                explanation="Multiple bytecode/class-path/config indicators appeared together, which is stronger than a single keyword.",
            )

        registry_tokens = {"module", "modulemanager", "module manager", "feature", "featuremanager", "feature manager", "category", "toggleable", "enabled", "keybind", "clickgui"}
        feature_tokens = {"triggerbot", "trigger bot", "killaura", "kill aura", "autoclicker", "auto clicker", "reach", "velocity", "antikb", "esp", "xray", "scaffold"}
        if self._has_any(tokens, registry_tokens) and self._has_any(tokens, feature_tokens):
            self._add_detection(
                result,
                rule_id="MODULE_REGISTRY_WITH_FEATURES",
                rule_name="Module registry with feature names",
                category="Client",
                severity="low",
                confidence=0.42,
                matched_keyword="module registry + feature names",
                source_type="heuristic",
                evidence_preview="module/feature registry tokens combined with combat/render/movement names",
                explanation="Client-style module registry names appear together with feature names. This should be reviewed with stronger findings.",
            )

    def _apply_package_role_heuristics(self, result: JarScanResult) -> None:
        class_path_tokens = result.source_tokens.get("class_path", set())
        roles = class_path_tokens.intersection(PACKAGE_ROLE_TOKENS)
        feature_terms = {"triggerbot", "trigger bot", "killaura", "kill aura", "reach", "velocity", "autoclicker", "auto clicker", "esp", "xray", "scaffold"}
        if len(roles) >= 3 and self._has_any(class_path_tokens, feature_terms):
            self._add_detection(
                result,
                rule_id="PACKAGE_ROLE_FEATURE_MATCH",
                rule_name="Package role feature match",
                category="Heuristic",
                severity="medium",
                confidence=0.68,
                matched_keyword="package role + feature",
                source_type="heuristic",
                evidence_preview=f"package roles: {', '.join(sorted(roles)[:6])}",
                explanation="Class packages look like client module roles and include suspicious feature names.",
            )

    def _apply_tree_heuristics(self, result: JarScanResult) -> None:
        summary = result.tree_summary
        if not summary:
            return
        if int(summary.get("root_class_count", 0)) >= 8 and result.class_count >= 20:
            self._add_detection(
                result,
                rule_id="TREE_ROOT_CLASS_DENSITY",
                rule_name="Unusual root class density",
                category="Structure",
                severity="low",
                confidence=0.42,
                matched_keyword="root classes",
                source_type="heuristic",
                evidence_preview=f"{summary.get('root_class_count')} class files at jar root",
                explanation="Many class files are located at the jar root, which is unusual for normal packaged mods.",
                context_type="tree_structure",
            )
        if float(summary.get("meaningless_dir_ratio", 0.0)) >= 0.38 and result.class_count >= 30:
            self._add_detection(
                result,
                rule_id="TREE_MEANINGLESS_DIRECTORIES",
                rule_name="Unusual directory tree",
                category="Structure",
                severity="low",
                confidence=0.42,
                matched_keyword="meaningless folders",
                source_type="heuristic",
                evidence_preview=f"meaningless directory ratio {summary.get('meaningless_dir_ratio')}",
                explanation="The jar has many short/random-looking internal package folders. This is weak alone and stronger with other evidence.",
                context_type="tree_structure",
            )
        class_tokens = result.source_tokens.get("class_path", set())
        if not result.metadata_files_found and result.class_count >= 20 and class_tokens.intersection(MODULE_MANAGER_TOKENS | FEATURE_CONTEXT_TOKENS):
            self._add_detection(
                result,
                rule_id="TREE_NO_METADATA_MODLIKE_CLASSES",
                rule_name="Mod-like classes without loader metadata",
                category="Structure",
                severity="medium",
                confidence=0.58,
                matched_keyword="missing metadata + module/client classes",
                source_type="heuristic",
                evidence_preview="metadata missing while client/module/feature packages exist",
                explanation="The jar lacks loader metadata but contains mod/client/module-like classes.",
                context_type="tree_structure",
            )
        package_roots = str(summary.get("top_package_roots", ""))
        file_tokens = set(tokens_for_text(result.file_name))
        package_tokens = set(tokens_for_text(package_roots))
        if result.mod_id:
            file_tokens.update(tokens_for_text(result.mod_id))
        if package_tokens and file_tokens and not file_tokens.intersection(package_tokens) and class_tokens.intersection(FEATURE_CONTEXT_TOKENS):
            self._add_detection(
                result,
                rule_id="TREE_NAME_PACKAGE_MISMATCH",
                rule_name="Name/package content mismatch",
                category="Structure",
                severity="medium",
                confidence=0.62,
                matched_keyword="name package mismatch",
                source_type="heuristic",
                evidence_preview=f"{result.file_name}: package roots {package_roots}",
                explanation="The filename or mod id does not line up with package roots while feature indicators appear in content.",
                context_type="tree_structure",
            )

    def _apply_loader_context_heuristics(self, result: JarScanResult) -> None:
        normalized_payloads = {
            path.replace("\\", "/").lower().strip("/")
            for path in result.opaque_payload_paths
        }
        rule_ids = {item.rule_id for item in result.detections}
        metadata_names = {
            path.replace("\\", "/").lower().strip("/")
            for path in result.metadata_files_found
        }
        direct_class_loader = "BYTECODE_DIRECT_CLASS_DEFINITION" in rule_ids
        native_memory_bridge = "BYTECODE_NATIVE_MEMORY_LOADER_BRIDGE" in rule_ids
        raw_payload_io = "BYTECODE_RAW_CHANNEL_PAYLOAD_IO" in rule_ids
        direct_classes = {
            self._normalize_class_name(item.class_name)
            for item in result.detections
            if item.rule_id == "BYTECODE_DIRECT_CLASS_DEFINITION" and item.class_name
        }
        native_classes = {
            self._normalize_class_name(item.class_name)
            for item in result.detections
            if item.rule_id == "BYTECODE_NATIVE_MEMORY_LOADER_BRIDGE" and item.class_name
        }
        raw_io_classes = {
            self._normalize_class_name(item.class_name)
            for item in result.detections
            if item.rule_id == "BYTECODE_RAW_CHANNEL_PAYLOAD_IO" and item.class_name
        }
        native_chain = self._shortest_class_chain(result, direct_classes, native_classes, max_depth=4)
        raw_io_chain = self._shortest_class_chain(result, direct_classes, raw_io_classes, max_depth=4)
        entry_chain = self._shortest_class_chain(result, result.entrypoint_classes, direct_classes, max_depth=3)
        direct_is_entrypoint = bool(direct_classes.intersection(result.entrypoint_classes))
        loader_graph_connected = bool(native_chain or raw_io_chain)
        loader_entry_reachable = direct_is_entrypoint or bool(entry_chain)
        opaque_bundle = (
            len(normalized_payloads) >= 4
            and result.opaque_payload_high_entropy >= 3
            and result.opaque_payload_bytes >= 256 * 1024
        )

        if opaque_bundle:
            self._add_detection(
                result,
                rule_id="OPAQUE_RESOURCE_PAYLOAD_BUNDLE",
                rule_name="Opaque extensionless payload bundle",
                category="Concealment",
                severity="high",
                confidence=0.9,
                matched_keyword="multiple high-entropy extensionless resources",
                source_type="resource",
                evidence_preview=(
                    f"{result.opaque_payload_high_entropy} high-entropy payloads / "
                    f"{result.opaque_payload_bytes} bytes: {', '.join(sorted(normalized_payloads)[:7])}"
                ),
                explanation="The archive stores several large high-entropy payloads without normal file extensions. This is correlated with executable loader behaviour before affecting the final verdict.",
                context_type="opaque_payload_bundle",
            )

        if opaque_bundle and direct_class_loader and loader_graph_connected:
            decisive_graph = bool(native_chain and raw_io_chain and loader_entry_reachable)
            graph_parts = []
            if entry_chain:
                graph_parts.append("entry " + " -> ".join(entry_chain))
            elif direct_is_entrypoint:
                graph_parts.append("loader is an entrypoint")
            if raw_io_chain:
                graph_parts.append("I/O " + " -> ".join(raw_io_chain))
            if native_chain:
                graph_parts.append("native " + " -> ".join(native_chain))
            self._add_detection(
                result,
                rule_id="BYTECODE_CONNECTED_OPAQUE_LOADER_GRAPH" if decisive_graph else "BYTECODE_OPAQUE_LOADER_GRAPH_SUPPORT",
                rule_name="Connected opaque payload-loader class graph",
                category="Concealment",
                severity="critical" if decisive_graph else "high",
                confidence=0.98 if decisive_graph else 0.88,
                matched_keyword="entrypoint/defineClass/payload/native graph",
                source_type="graph",
                evidence_preview="; ".join(graph_parts)[:220],
                explanation=(
                    "The direct class loader, raw payload transport, and native-memory bridge are connected through real internal class references and the loader is reachable from an entrypoint."
                    if decisive_graph
                    else "Opaque payload and loader capabilities are connected in the internal class graph, but the full entrypoint/I-O/native chain was not proven; this remains supporting evidence."
                ),
                context_type="loader_class_graph",
            )

        concealed_agent_loader = (
            result.java_agent_manifest
            and result.java_agent_retransform
            and direct_class_loader
            and native_memory_bridge
            and opaque_bundle
            and loader_graph_connected
        )
        if concealed_agent_loader:
            supporting = ["Java Agent retransform", "resource-backed defineClass", "JNA native-memory bridge", "opaque payload bundle"]
            if raw_payload_io:
                supporting.append("raw socket/file payload I/O")
            self._add_detection(
                result,
                rule_id="BYTECODE_CONCEALED_AGENT_PAYLOAD_LOADER",
                rule_name="Concealed Java-agent payload loader",
                category="Concealment",
                severity="critical",
                confidence=0.99,
                matched_keyword=" + ".join(supporting),
                source_type="behavior_correlation",
                evidence_preview=f"{result.file_name}: {'; '.join(supporting)}",
                explanation="Independent active behaviours show an obfuscated Java agent that loads hidden archive resources as JVM/native code. A filename change does not affect this structural detection.",
                context_type="concealed_agent_loader",
            )

        doomsday_payload_names = {f"net/java/{letter}" for letter in "abcde"}
        doomsday_payload_count = len(normalized_payloads.intersection(doomsday_payload_names))
        loader_metadata_count = len(metadata_names.intersection({
            "fabric.mod.json", "meta-inf/mods.toml", "mcmod.info",
        }))
        doomsday_layout = (
            concealed_agent_loader
            and result.mod_id.lower().strip() == "dd"
            and "64fv7p4h2no7q" in normalized_payloads
            and doomsday_payload_count >= 4
            and loader_metadata_count >= 2
            and result.class_count >= 8
            and result.obfuscation_ratio >= 0.8
        )
        if doomsday_layout:
            result.family_id = "doomsday-concealed-loader"
            result.family_similarity = 1.0
            self._add_detection(
                result,
                rule_id="DOOMSDAY_STRUCTURAL_FAMILY",
                rule_name="Doomsday concealed-loader family",
                category="Known Client Family",
                severity="critical",
                confidence=0.995,
                matched_keyword="Doomsday internal loader layout",
                source_type="behavior_correlation",
                evidence_preview=(
                    f"mod id dd; agent retransform; 64FV7P4H2NO7Q carrier; "
                    f"{doomsday_payload_count}/5 net/java/a-e payloads; direct class/native loader"
                ),
                explanation="The internal entrypoint, payload names, obfuscated class layout, Java-agent capabilities, direct class definition, and native-memory bridge match the Doomsday loader family. The external JAR filename is not used for this match.",
                context_type="known_client_structure",
            )

        tokens = result.analysis_tokens
        if not tokens:
            return
        if result.loader_type == "Unknown" and result.class_count >= 15 and tokens.intersection(MINECRAFT_API_MARKERS | MIXIN_TARGET_TOKENS):
            self._add_detection(
                result,
                rule_id="UNKNOWN_LOADER_CLIENT_CONTEXT",
                rule_name="Unknown loader client context",
                category="Structure",
                severity="low",
                confidence=0.4,
                matched_keyword="unknown loader + client api",
                source_type="heuristic",
                evidence_preview="no loader metadata but Minecraft client APIs are referenced",
                explanation="Loader metadata is missing while client-side Minecraft references are present.",
                context_type="loader_context",
            )
        if result.client_side and tokens.intersection(FEATURE_CONTEXT_TOKENS):
            self._add_detection(
                result,
                rule_id="CLIENT_SIDE_FEATURE_CONTEXT",
                rule_name="Client-side feature context",
                category="Client",
                severity="medium",
                confidence=0.68,
                matched_keyword="client side feature",
                source_type="heuristic",
                evidence_preview=f"{result.loader_type} client-side metadata with feature tokens",
                explanation="The mod is client-side and also contains combat/render/movement feature indicators.",
                context_type="loader_context",
            )
        if not result.metadata_files_found and result.class_count >= 10:
            self._add_detection(
                result,
                rule_id="MISSING_METADATA_SUPPORT_SIGNAL",
                rule_name="Missing loader metadata support signal",
                category="Structure",
                severity="low",
                confidence=0.32,
                matched_keyword="missing metadata",
                source_type="heuristic",
                evidence_preview="no fabric/quilt/forge metadata found",
                explanation="Missing loader metadata is a weak support signal only and should be read with other evidence.",
                context_type="loader_context",
            )

    def _shortest_class_chain(
        self,
        result: JarScanResult,
        sources: set[str],
        targets: set[str],
        max_depth: int = 4,
    ) -> list[str]:
        """Return a bounded internal reference path between two capability sets."""
        normalized_sources = {self._normalize_class_name(value) for value in sources if value}
        normalized_targets = {self._normalize_class_name(value) for value in targets if value}
        if not normalized_sources or not normalized_targets:
            return []
        internal = {self._normalize_class_name(value) for value in result.class_references}
        adjacency = {
            self._normalize_class_name(owner): {
                self._normalize_class_name(ref)
                for ref in refs
                if self._normalize_class_name(ref) in internal
            }
            for owner, refs in result.class_references.items()
        }
        queue: list[tuple[str, list[str]]] = [(source, [source]) for source in sorted(normalized_sources)]
        seen = set(normalized_sources)
        while queue:
            current, chain = queue.pop(0)
            if current in normalized_targets:
                return chain
            if len(chain) - 1 >= max_depth:
                continue
            for neighbor in sorted(adjacency.get(current, set())):
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                queue.append((neighbor, [*chain, neighbor]))
        return []

    def _apply_graph_heuristics(self, result: JarScanResult) -> None:
        for class_name, refs in result.class_references.items():
            class_tokens = set(tokens_for_text(class_name))
            ref_tokens = set(tokens_for_text(" ".join(refs)))
            if class_name in result.entrypoint_classes and ref_tokens.intersection(MODULE_MANAGER_TOKENS):
                self._add_detection(
                    result,
                    rule_id="ENTRYPOINT_MODULE_MANAGER_LINK",
                    rule_name="Entrypoint module manager link",
                    category="Graph",
                    severity="medium",
                    confidence=0.72,
                    matched_keyword="entrypoint -> module manager",
                    source_type="graph",
                    evidence_preview=f"{class_name}: refs {', '.join(sorted(ref_tokens.intersection(MODULE_MANAGER_TOKENS))[:4])}",
                    explanation="Entrypoint class references module/feature manager style classes.",
                    context_type="class_graph",
                )
            if class_tokens.intersection(MODULE_MANAGER_TOKENS) and ref_tokens.intersection(FEATURE_CONTEXT_TOKENS):
                self._add_detection(
                    result,
                    rule_id="MODULE_MANAGER_FEATURE_LINK",
                    rule_name="Module manager feature link",
                    category="Graph",
                    severity="high",
                    confidence=0.82,
                    matched_keyword="module manager -> feature",
                    source_type="graph",
                    evidence_preview=f"{class_name}: refs feature tokens {', '.join(sorted(ref_tokens.intersection(FEATURE_CONTEXT_TOKENS))[:5])}",
                    explanation="Module/feature manager style class references combat/render/movement feature classes.",
                    context_type="class_graph",
                )
        if result.access_widener_targets and result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS):
            self._add_detection(
                result,
                rule_id="ACCESS_WIDENER_FEATURE_CONTEXT",
                rule_name="Access widener feature context",
                category="Access Widener",
                severity="medium",
                confidence=0.7,
                matched_keyword="access widener + feature",
                source_type="access_widener",
                evidence_preview="targets: " + ", ".join(sorted(result.access_widener_targets)[:3]),
                explanation="Access widener exposes sensitive client/player/render classes while feature indicators are present.",
                context_type="access_widener",
            )

    def _apply_module_system_heuristics(self, result: JarScanResult) -> None:
        if result.module_system_score < 45:
            return
        has_feature = bool(result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS))
        severity = "medium" if has_feature else "low"
        confidence = 0.72 if has_feature else 0.42
        self._add_detection(
            result,
            rule_id="MODULE_SYSTEM_SHAPE",
            rule_name="Module system shape",
            category="Client",
            severity=severity,
            confidence=confidence,
            matched_keyword="module system shape",
            source_type="graph",
            evidence_preview=f"module_system_score={result.module_system_score}",
            explanation="Classes and constants resemble a client module system with module manager, settings, keybind, toggle, and lifecycle methods.",
            context_type="module_system",
        )

    def _apply_build_metadata_heuristics(self, result: JarScanResult) -> None:
        self._update_package_trust(result)
        artifact = result.build_metadata.get("artifactId") or result.build_metadata.get("archives_base_name") or ""
        metadata_tokens = set(tokens_for_text(" ".join([result.file_name, result.mod_id, result.mod_name])))
        build_tokens = set(tokens_for_text(artifact))
        package_tokens = set(tokens_for_text(str(result.tree_summary.get("top_package_roots", "")) if result.tree_summary else ""))
        suspicious_build = build_tokens.intersection(FEATURE_CONTEXT_TOKENS | MODULE_MANAGER_TOKENS)
        if suspicious_build and metadata_tokens and not metadata_tokens.intersection(build_tokens):
            self._add_detection(
                result,
                rule_id="BUILD_METADATA_CONTENT_MISMATCH",
                rule_name="Build metadata content mismatch",
                category="Structure",
                severity="medium",
                confidence=0.68,
                matched_keyword=artifact,
                source_type="metadata",
                evidence_preview=f"artifactId={artifact}; packages={result.tree_summary.get('top_package_roots', '') if result.tree_summary else ''}",
                explanation="Filename or declared mod metadata does not match build artifact/package semantics.",
                context_type="metadata_mismatch",
            )
        if result.package_trust == "benign_prefix_with_strong_feature" and result.strong_evidence_count:
            self._add_detection(
                result,
                rule_id="BENIGN_PREFIX_STRONG_CONTENT_MISMATCH",
                rule_name="Benign prefix with strong feature content",
                category="Structure",
                severity="medium",
                confidence=0.62,
                matched_keyword="prefix/content mismatch",
                source_type="heuristic",
                evidence_preview=f"package roots={result.tree_summary.get('top_package_roots', '') if result.tree_summary else ''}",
                explanation="A benign-looking package prefix appears together with strong feature indicators, so the prefix is not trusted blindly.",
                context_type="metadata_mismatch",
            )

    def _apply_post_entry_contexts(self, result: JarScanResult) -> None:
        entry_packages = {self._package_prefix(value) for value in result.entrypoint_classes if value}
        for class_name, feature_tokens in result.class_feature_tokens.items():
            if not feature_tokens:
                continue
            package = self._package_prefix(class_name)
            if package and package in entry_packages:
                self._add_detection(
                    result,
                    rule_id="ENTRYPOINT_NEAR_FEATURE",
                    rule_name="Entrypoint-near feature class",
                    category="Graph",
                    severity="high",
                    confidence=0.82,
                    matched_keyword=", ".join(sorted(feature_tokens)[:3]),
                    source_type="graph",
                    evidence_preview=f"{class_name}: same package area as entrypoint",
                    explanation="Suspicious feature class is near an entrypoint package, which makes it more relevant than a stray string.",
                    context_type="class_graph",
                )

    def _analyze_tree_structure(self, result: JarScanResult, names: list[str]) -> None:
        class_names = [name for name in names if name.lower().endswith(".class")]
        dirs: Counter[str] = Counter()
        root_classes = 0
        for name in class_names:
            parts = name.split("/")
            if len(parts) == 1:
                root_classes += 1
            for part in parts[:-1]:
                dirs[part.lower()] += 1
        meaningless = 0
        for directory in dirs:
            compact = re.sub(r"[^a-z0-9]", "", directory)
            if len(compact) <= 2 or is_randomish_name(f"{compact}.jar"):
                meaningless += 1
        top_roots = [item for item, _count in Counter(name.split("/", 1)[0].lower() for name in class_names if "/" in name).most_common(4)]
        result.tree_summary = {
            "class_count": len(class_names),
            "directory_count": len(dirs),
            "root_class_count": root_classes,
            "meaningless_dir_ratio": round(meaningless / max(1, len(dirs)), 3),
            "top_package_roots": ",".join(top_roots),
        }

    def _local_search_roots(self) -> list[Path]:
        roots = [Path.cwd(), Path(__file__).resolve().parents[1]]
        if getattr(sys, "frozen", False):
            roots.append(Path(sys.executable).resolve().parent)
        out: list[Path] = []
        seen: set[str] = set()
        for root in roots:
            try:
                resolved = root.resolve()
            except OSError:
                resolved = root
            key = str(resolved).lower()
            if key not in seen:
                seen.add(key)
                out.append(resolved)
        return out

    def _default_cache_dir(self) -> Path:
        base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]
        return base / "xien_control_cache"

    def _instance_context(self, location: LauncherLocation, result: JarScanResult | None) -> str:
        parts = [location.launcher_name, location.instance_name]
        if result is not None:
            parts.append(result.file_name)
        text = " / ".join(part for part in parts if part)
        tokens = set(tokens_for_text(text))
        if tokens.intersection({"pvp", "practice", "ghost", "fps", "client", "hypixel"}):
            return text
        return f"{location.launcher_name} / {location.instance_name}"

    def _apply_known_hashes(self, result: JarScanResult) -> None:
        digest = result.sha256.lower()
        for bucket, severity, verdict_hint in (
            ("known_blocked", "critical", "blocked"),
            ("known_review", "medium", "review"),
            ("known_clean", "info", "clean"),
        ):
            if digest not in self.known_hashes.get(bucket, {}):
                continue
            result.known_hash_status = verdict_hint
            if bucket == "known_clean":
                return
            self._add_detection(
                result,
                rule_id=f"LOCAL_HASH_{bucket.upper()}",
                rule_name=f"Local hash list: {verdict_hint}",
                category="Hash",
                severity=severity,
                confidence=0.98,
                matched_keyword=digest,
                source_type="hash",
                evidence_preview=f"{result.file_name}: sha256 {digest}",
                explanation="SHA-256 matched a local known_hashes.json list entry.",
                context_type="hash",
            )
            return

    def _apply_allowlist(self, result: JarScanResult) -> None:
        digest = result.sha256.lower()
        if digest in self.allowlist.get("allowed_hashes", set()):
            result.allowlisted = True
            result.allowlist_notes.append("hash")
        mod_id = result.mod_id.lower().strip()
        if mod_id and mod_id in self.allowlist.get("allowed_mod_ids", set()):
            result.allowlisted = True
            result.allowlist_notes.append(f"mod_id:{mod_id}")

    def _prioritized_infos(self, infos: list[zipfile.ZipInfo], result: JarScanResult) -> list[zipfile.ZipInfo]:
        def priority(info: zipfile.ZipInfo) -> tuple[int, str]:
            name = info.filename.replace("\\", "/")
            lower = name.lower()
            if lower in METADATA_FILES_LOWER or lower.endswith("manifest.mf"):
                return (0, lower)
            if MIXIN_FILE_RE.search(lower) or lower.endswith(".accesswidener") or lower.startswith(SERVICE_PREFIX):
                return (1, lower)
            if lower.endswith(".class") and self._is_entrypoint_related_class(lower, result):
                return (2, lower)
            if lower.endswith(".class") and self._feature_tokens(lower):
                return (3, lower)
            if LANG_FILE_RE.search(lower) or self._is_config_candidate(lower):
                return (4, lower)
            if lower.endswith(".class"):
                return (5, lower)
            return (6, lower)

        return sorted(infos, key=priority)

    def _finalize_analysis_summary(self, result: JarScanResult) -> None:
        self._finalize_versions_and_class_versions(result)
        self._validate_entrypoints(result)
        classify_packages(result)
        analyze_reachability(result)
        compute_token_vectors(result)
        self._apply_client_name_matches(result)
        self._apply_advanced_context_heuristics(result)
        build_fingerprints(result)
        result.sources_analyzed_count = sum(1 for values in result.source_tokens.values() if values)
        if result.error:
            result.analysis_status = "FAILED_ANALYSIS"
            result.analysis_confidence_score = 10
        elif result.truncated or (result.class_count and result.classes_analyzed_count < result.class_count):
            result.analysis_status = "PARTIAL_ANALYSIS"
            result.analysis_confidence_score = 45
        else:
            result.analysis_status = "FULL_ANALYSIS"
            result.analysis_confidence_score = 65
        if result.metadata_files_found:
            result.analysis_confidence_score += 8
        if result.classes_analyzed_count >= 10:
            result.analysis_confidence_score += 10
        if result.resources_analyzed_count >= 3:
            result.analysis_confidence_score += 7
        if result.mixin_files_found or result.access_widener_files_found or result.service_entries_found:
            result.analysis_confidence_score += 6
        if result.structure_fingerprint:
            result.analysis_confidence_score += 4
        if result.parsed_attributes_count:
            result.analysis_confidence_score += 5
        if result.package_classifications:
            result.analysis_confidence_score += 4
        if result.feature_reachability in {"REACHABLE", "POSSIBLY_REACHABLE"}:
            result.analysis_confidence_score += 5
        if result.obfuscated_string_score >= 30 and result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS):
            self._add_detection(
                result,
                rule_id="OBFUSCATED_STRING_TABLE_WITH_FEATURE",
                rule_name="Obfuscated string table with feature context",
                category="String",
                severity="medium",
                confidence=0.58,
                matched_keyword="string table",
                source_type="string",
                evidence_preview=f"obfuscated_string_score={result.obfuscated_string_score}",
                explanation="String table patterns look obfuscated and feature indicators are also present.",
                context_type="string_table",
            )
        result.analysis_confidence_score = min(100, result.analysis_confidence_score)
        if result.analysis_confidence_score >= 75:
            result.analysis_confidence = "High"
        elif result.analysis_confidence_score >= 45:
            result.analysis_confidence = "Medium"
        else:
            result.analysis_confidence = "Low"
        result.confidence_reasons = confidence_explanations(result)
        result.why_flagged = self._why_flagged(result)

    def _apply_client_name_matches(self, result: JarScanResult) -> None:
        identity_values = [result.file_name, result.mod_id, result.mod_name]
        matches = find_client_name_matches(identity_values, allow_fuzzy=True)
        structural_values = list(result.class_references)[:20000]
        # Class/package names are noisier than the jar identity.  Require
        # explicit client/hack context for ambiguous short names (notably a
        # bare ``wurst`` token) so ordinary classes do not become high-risk
        # client detections.
        matches.extend(find_client_name_matches(structural_values, allow_fuzzy=False, strict_context=True))
        seen_families: set[str] = set()
        for match in matches:
            if match.family in seen_families:
                continue
            seen_families.add(match.family)
            fuzzy = match.kind == "similar-name"
            self._add_detection(
                result,
                rule_id="KNOWN_CLIENT_NAME_SIMILAR" if fuzzy else "KNOWN_CLIENT_NAME_EXACT",
                rule_name="Known cheat client name similarity" if fuzzy else "Known cheat client identity",
                category="ClientIdentity",
                severity="high",
                confidence=round(0.72 if fuzzy else 0.94, 2),
                matched_keyword=match.family,
                source_type="identity",
                evidence_preview=f"{match.candidate} -> {match.family} ({match.kind}, {match.similarity:.0%})",
                explanation="A mod identity, package, or class name matches a researched Minecraft cheat-client family.",
                context_type="client_identity",
            )

    def _finalize_versions_and_class_versions(self, result: JarScanResult) -> None:
        result.filename_version = self._filename_version(result.file_name)
        if not result.metadata_version:
            result.metadata_version = result.mod_version or result.maven_version or result.implementation_version
        if result.filename_version and result.metadata_version:
            result.version_consistency = "CONSISTENT" if self._version_family(result.filename_version) == self._version_family(result.metadata_version) else "MISMATCHED"
        elif result.filename_version or result.metadata_version:
            result.version_consistency = "MISSING"
        else:
            result.version_consistency = "MISSING"

        if result.class_version_counts:
            majors = sorted(result.class_version_counts)
            result.min_class_major = majors[0]
            result.max_class_major = majors[-1]
            result.dominant_class_major = max(result.class_version_counts, key=result.class_version_counts.get)
            result.mixed_class_versions = len(majors) > 1

    def _validate_entrypoints(self, result: JarScanResult) -> None:
        if not result.entrypoint_classes:
            result.entrypoint_validation = "MISSING"
            return
        available = set(result.class_references) | set(result.class_feature_tokens) | set(result.class_roles)
        found = result.entrypoint_classes.intersection(available)
        if found:
            result.entrypoint_validation = "VALID"
            return
        result.entrypoint_validation = "DECLARED_BUT_NOT_FOUND"
        self._add_detection(
            result,
            rule_id="ENTRYPOINT_DECLARED_NOT_FOUND",
            rule_name="Declared entrypoint not found",
            category="Structure",
            severity="low",
            confidence=0.38,
            matched_keyword="entrypoint missing",
            source_type="metadata",
            evidence_preview="metadata entrypoint class was declared but not found in scanned class index",
            explanation="Loader metadata declares entrypoint classes that were not found or could not be parsed in the jar.",
            context_type="loader_context",
        )

    def _apply_advanced_context_heuristics(self, result: JarScanResult) -> None:
        if result.setting_model_score >= 28 and result.module_system_score >= 45 and result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS):
            self._add_detection(
                result,
                rule_id="SETTING_OBJECT_MODEL_FEATURE_CONTEXT",
                rule_name="Setting object model with feature context",
                category="Client",
                severity="medium",
                confidence=0.68,
                matched_keyword="settings + modules + features",
                source_type="graph",
                evidence_preview=f"setting_model_score={result.setting_model_score}; module_system_score={result.module_system_score}",
                explanation="Setting classes, module classes, and combat/render/movement feature names appear together.",
                context_type="module_system",
            )
        if (
            result.gui_context_score >= 18
            and result.module_system_score >= 45
            and result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS)
            and result.analysis_tokens.intersection(MODULE_MANAGER_TOKENS)
        ):
            self._add_detection(
                result,
                rule_id="GUI_MODULE_UI_CONTEXT",
                rule_name="Module GUI context",
                category="Client",
                severity="low",
                confidence=0.42,
                matched_keyword="module gui",
                source_type="graph",
                evidence_preview=f"gui_context_score={result.gui_context_score}",
                explanation="GUI/screen classes appear near module category or setting tokens. This is context only.",
                context_type="gui_context",
            )
        if result.version_consistency == "MISMATCHED" and result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS):
            self._add_detection(
                result,
                rule_id="VERSION_METADATA_MISMATCH",
                rule_name="Version metadata mismatch",
                category="Structure",
                severity="low",
                confidence=0.42,
                matched_keyword="version mismatch",
                source_type="version",
                evidence_preview=f"filename={result.filename_version}; metadata={result.metadata_version}",
                explanation="Filename version and declared metadata version do not match while feature context is present.",
                context_type="metadata_mismatch",
            )
        if result.signature_status == "SIGNATURE_METADATA_INCOMPLETE":
            self._add_detection(
                result,
                rule_id="SIGNATURE_METADATA_INCOMPLETE",
                rule_name="Signature metadata incomplete",
                category="Integrity",
                severity="low",
                confidence=0.34,
                matched_keyword="signature incomplete",
                source_type="signature",
                evidence_preview="META-INF signature files are incomplete or inconsistent",
                explanation="Signature metadata exists but appears incomplete. This is an integrity note, not a standalone cheat verdict.",
                context_type="integrity",
            )
        if result.zip_anomalies:
            self._add_detection(
                result,
                rule_id="ZIP_STRUCTURE_ANOMALY",
                rule_name="Zip structure anomaly",
                category="Integrity",
                severity="low",
                confidence=0.32,
                matched_keyword="zip anomaly",
                source_type="zip",
                evidence_preview="; ".join(result.zip_anomalies[:2]),
                explanation="The archive has unusual ZIP structure metadata. This is a support signal only.",
                context_type="integrity",
            )
        if result.mixed_class_versions and result.version_consistency == "MISMATCHED":
            self._add_detection(
                result,
                rule_id="MIXED_CLASS_VERSION_CONTEXT",
                rule_name="Mixed class version context",
                category="Structure",
                severity="low",
                confidence=0.34,
                matched_keyword="mixed class versions",
                source_type="metadata",
                evidence_preview=f"class major range {result.min_class_major}-{result.max_class_major}",
                explanation="Class Java version distribution is mixed while metadata/version naming is inconsistent.",
                context_type="class_version",
            )
        if result.declared_dependencies and result.mod_id and result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS):
            dep_tokens = set(tokens_for_text(" ".join(result.declared_dependencies | result.provided_ids | result.conflicting_ids)))
            id_tokens = set(tokens_for_text(result.mod_id))
            if dep_tokens and not dep_tokens.intersection(id_tokens) and result.renamed_suspicious:
                self._add_detection(
                    result,
                    rule_id="DEPENDENCY_IDENTITY_MISMATCH_CONTEXT",
                    rule_name="Dependency identity mismatch context",
                    category="Structure",
                    severity="low",
                    confidence=0.38,
                    matched_keyword="dependency mismatch",
                    source_type="dependency",
                    evidence_preview="declared dependency/provided ids do not line up with suspicious internal content",
                    explanation="Dependency metadata helps confirm this jar should be reviewed as its own mod, not just a shaded library.",
                    context_type="dependency_context",
                )

    def _filename_version(self, name: str) -> str:
        match = re.search(r"(?:^|[-_])v?([0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9_.-]+)?)(?=\D|$)", name)
        return match.group(1) if match else ""

    def _version_family(self, value: str) -> str:
        parts = re.findall(r"\d+", value)
        return ".".join(parts[:3])

    def _collect_metadata_versions(self, result: JarScanResult, data: object) -> None:
        text = json.dumps(data, default=str).lower() if not isinstance(data, str) else data.lower()
        for version in re.findall(r"(?:minecraft|mc)[^0-9]{0,20}([0-9]+(?:\.[0-9]+){1,2})", text):
            if version not in result.minecraft_versions:
                result.minecraft_versions.append(version)
        for version in re.findall(r"(?:fabricloader|forge|quilt_loader|loader)[^0-9]{0,20}([0-9]+(?:\.[0-9]+){1,3})", text):
            if version not in result.loader_versions:
                result.loader_versions.append(version)

    def _is_entrypoint_related_class(self, lower_path: str, result: JarScanResult) -> bool:
        normalized = self._normalize_class_name(lower_path)
        if normalized in result.entrypoint_classes:
            return True
        package = self._package_prefix(normalized)
        return bool(package and any(self._package_prefix(item) == package for item in result.entrypoint_classes))

    def _normalize_class_name(self, value: str) -> str:
        value = str(value).strip().replace("\\", "/")
        value = re.sub(r"\.class$", "", value, flags=re.IGNORECASE)
        value = value.replace(".", "/")
        value = value.strip("/")
        return value.lower()

    def _package_prefix(self, value: str) -> str:
        normalized = self._normalize_class_name(value)
        parts = normalized.split("/")
        if len(parts) <= 1:
            return ""
        return "/".join(parts[:-1])

    def _feature_tokens(self, text: str) -> set[str]:
        tokens = set(tokens_for_text(text))
        compact = "".join(tokens_for_text(text))
        ambiguous = {"reach", "velocity"}
        out = tokens.intersection(FEATURE_CONTEXT_TOKENS - ambiguous)
        ambiguous_context = {"attack", "combat", "feature", "features", "knockback", "mixin", "module", "modules", "packet", "setting", "settings"}
        for feature in ambiguous:
            if feature in tokens and tokens.intersection(ambiguous_context):
                out.add(feature)
        for feature in FEATURE_CONTEXT_TOKENS - ambiguous:
            # Concatenated identifiers such as KillAura still need matching,
            # while short/ambiguous words remain token-boundary based.
            if len(feature) >= 7 and feature in compact:
                out.add(feature)
        lowered = text.lower().replace("\\", "/")
        if "longjump" in out and any(marker in lowered for marker in ("/ai/task/", "longjumptorandompos", "longjumpchoicelist", "long_jump_weighted_choice")):
            out.discard("longjump")
        return out

    def _api_tokens(self, text: str) -> set[str]:
        compact = "".join(tokens_for_text(text))
        out: set[str] = set()
        for marker in MINECRAFT_API_MARKERS | MIXIN_TARGET_TOKENS:
            if marker in compact:
                out.add(marker)
        out.update(self.mapping_hints.contexts_for_text(text))
        return out

    def _score_module_system(self, result: JarScanResult, class_name: str, strings: list[str]) -> None:
        text = " ".join([class_name, *strings[:200]])
        tokens = set(tokens_for_text(text))
        compact = "".join(tokens)
        score = 0
        score += 18 if {"module", "manager"}.issubset(tokens) or "modulemanager" in compact else 0
        score += 14 if tokens.intersection({"category", "combat", "render", "movement"}) else 0
        score += 14 if tokens.intersection({"setting", "booleansetting", "numbersetting", "modesetting"}) else 0
        score += 12 if tokens.intersection({"keybind", "toggle", "enabled", "disabled"}) else 0
        score += 12 if tokens.intersection({"onenable", "ondisable", "ontick", "onrender", "onupdate"}) else 0
        score += 18 if tokens.intersection(FEATURE_CONTEXT_TOKENS) else 0
        if score:
            result.module_system_score = min(100, result.module_system_score + score)

    def _score_obfuscated_strings(self, result: JarScanResult, strings: list[str]) -> None:
        if not strings:
            return
        short = 0
        base64_like = 0
        randomish = 0
        for value in strings[:600]:
            compact = re.sub(r"[^A-Za-z0-9+/=_-]", "", value)
            if 4 <= len(value) <= 8:
                short += 1
            if len(compact) >= 16 and re.match(r"^[A-Za-z0-9+/=_-]+$", compact):
                base64_like += 1
            if is_randomish_name(f"{value}.jar"):
                randomish += 1
        density = short + base64_like * 2 + randomish * 2
        if density >= 40:
            result.obfuscated_string_score = min(100, result.obfuscated_string_score + min(40, density // 4))

    def _update_package_trust(self, result: JarScanResult) -> None:
        roots = set(tokens_for_text(str(result.tree_summary.get("top_package_roots", "")) if result.tree_summary else ""))
        if not roots:
            result.package_trust = "unknown"
            return
        if roots.intersection(BENIGN_PREFIX_TOKENS):
            result.package_trust = "benign_prefix_with_strong_feature" if result.analysis_tokens.intersection(FEATURE_CONTEXT_TOKENS) else "benign_prefix"
            return
        meaningless = float(result.tree_summary.get("meaningless_dir_ratio", 0.0)) if result.tree_summary else 0.0
        result.package_trust = "random_or_unknown" if meaningless >= 0.3 else "unknown"

    def _classify_text_context(self, text: str, evidence: str = "") -> str:
        value = str(text)
        combined = f"{evidence} {value}"
        lower = combined.lower()
        tokens = set(tokens_for_text(combined))
        if LANG_FILE_RE.search(lower) or re.search(r"\b(module|setting|option)\.[a-z0-9_.-]+", lower):
            return "translation_key"
        if "=" in value or ":" in value and tokens.intersection(GUI_SETTING_TOKENS):
            return "config_key"
        if "/" in value and re.search(r"[a-z0-9_$]+/[a-z0-9_$/]+", value, re.IGNORECASE):
            return "package_path"
        if re.match(r"^[A-Za-z_$][A-Za-z0-9_$.]+$", value) and ("." in value or "/" in value):
            return "class_like"
        if re.match(r"^[a-zA-Z_$][a-zA-Z0-9_$]{2,40}$", value):
            return "method_like"
        if tokens.intersection(GUI_SETTING_TOKENS) and tokens.intersection(FEATURE_CONTEXT_TOKENS):
            return "gui_label"
        if "http://" in lower or "https://" in lower or re.search(r"^[a-z0-9_.-]+:[a-z0-9_/.-]+$", lower):
            return "url_or_id"
        if any(word in lower for word in ("enabled", "disabled", "loaded", "failed", "error")):
            return "log_message"
        if len(tokens) <= 1:
            return "random_text"
        return "random_text"

    def _scan_gui_context(self, result: JarScanResult, keyword: str, evidence: str, class_name: str) -> None:
        tokens = set(tokens_for_text(f"{keyword} {evidence}"))
        features = self._feature_tokens(f"{keyword} {evidence}")
        controls = tokens.intersection(GUI_SETTING_TOKENS)
        if not features or not controls:
            return
        matched_pairs = {
            feature: sorted(controls.intersection(CHEAT_GUI_FEATURE_CONTROLS.get(feature, set())))
            for feature in features
            if controls.intersection(CHEAT_GUI_FEATURE_CONTROLS.get(feature, set()))
        }
        if not matched_pairs:
            return
        pair_text = ", ".join(f"{feature} + {'/'.join(values)}" for feature, values in sorted(matched_pairs.items()))
        self._add_detection(
            result,
            rule_id="GUI_FEATURE_SETTING_CONTEXT",
            rule_name="GUI feature setting context",
            category="Config",
            severity="medium",
            confidence=0.74,
            matched_keyword=pair_text,
            source_type="string",
            evidence_preview=f"{class_name}: {evidence}",
            explanation="GUI text contains a cheat-feature-specific control pair, such as autoclicker+CPS, aim assist+rotation, or reach+range.",
            context_type="gui_label",
        )

    def _why_flagged(self, result: JarScanResult) -> list[str]:
        why: list[str] = []
        sources = {item.source_type for item in result.detections}
        categories = {item.category for item in result.detections}
        if "class_path" in sources:
            why.append("Feature indicator found in class/package path.")
        if "string" in sources or "config" in sources or "translation" in sources:
            why.append("Feature confirmed in constants, config, GUI text, or translations.")
        if "mixin" in sources or "access_widener" in sources:
            why.append("Sensitive client/player/render hook context is present.")
        if "graph" in sources:
            why.append("Class references connect entrypoint/module/feature/client API areas.")
        if "ownership" in sources or "reachability" in sources:
            why.append("Feature evidence is tied to mod-owned or reachable code.")
        if {"source_file_attribute", "local_variable_table", "annotation_attribute"}.intersection(sources):
            why.append("Bytecode attributes expose feature, debug, or hook context.")
        if result.renamed_suspicious or "Structure" in categories:
            why.append("Filename, metadata, or internal package structure does not line up cleanly.")
        if result.allowlisted:
            why.append("Local allowlist matched; verdict was softened, not ignored.")
        return why[:3]

    def _has_any(self, tokens: set[str], values: set[str]) -> bool:
        return bool(tokens.intersection(values))

    def _has_all(self, tokens: set[str], values: set[str]) -> bool:
        return values.issubset(tokens)

    def _package_context_score(self, class_path: str) -> int:
        tokens = path_tokens(class_path)
        score = 0
        if tokens.intersection(HARD_PACKAGE_TOKENS):
            score += 3
        if len(tokens.intersection(SOFT_PACKAGE_TOKENS)) >= 2:
            score += 1
        return score

    def _clean_preview(self, value: str) -> str:
        compact = re.sub(r"\s+", " ", str(value)).strip()
        return compact[:MAX_EVIDENCE_PREVIEW]

def _deep_audit_signal_entry(path: str) -> bool:
    """Keep deep marker evidence out of documentation/localization noise."""
    lower = path.replace("\\", "/").lower()
    if any(part in lower for part in DEEP_AUDIT_IGNORED_PATH_PARTS):
        return False
    return lower.endswith(DEEP_AUDIT_ACTIVE_SUFFIXES) or "/config/" in lower or lower.startswith("config/")


def _deep_audit_marker_severity(marker: str, path: str, configured: str) -> str:
    if marker == "mousetweaks":
        return "low"
    lower = path.replace("\\", "/").lower()
    # A marker in an explicitly named feature class/config is materially
    # stronger than a generic utility class that merely contains a string.
    stem_tokens = set(tokens_for_text(Path(lower).stem))
    path_tokens_set = set(tokens_for_text(lower))
    explicit_context = {"module", "modules", "feature", "features", "client", "hack", "combat", "movement", "render", "mixin"}
    if marker in stem_tokens or "/config/" in lower or path_tokens_set.intersection(explicit_context):
        return configured
    return "medium"


def _shannon_entropy(data: bytes) -> float:
    """Return byte entropy for deep-audit obfuscation evidence."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * __import__("math").log2(count / length) for count in counts.values())


def _opaque_payload_format(data: bytes) -> str:
    """Identify executable container magic hidden behind an extensionless path."""
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return "JVM class"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP/JAR archive"
    if len(data) >= 0x44 and data[:2] == b"MZ":
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if 0x40 <= pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            return "PE executable"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP stream"
    return ""
