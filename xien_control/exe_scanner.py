from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable

from .exe_artifacts import ExeArtifactDatabase
from .exe_cache import ExeAnalysisCache
from .exe_discovery import ExeDiscovery
from .exe_models import ExeScanResult, ExeScanSummary
from .exe_risk import score_exe
from .exe_rules import apply_identity_context, classify_folder, import_categories, review_priority
from .pe_parser import parse_pe
from .pe_signature import check_signature
from .pe_strings import classify_strings, extract_pe_strings
from .utils import human_size, sha256_file


LogFn = Callable[[str, str], None]
ProgressFn = Callable[[int, int, str], None]

LARGE_EXE_BYTES = 128 * 1024 * 1024
MAX_STRING_SCAN_BYTES = 8 * 1024 * 1024


class WindowsExeScanner:
    def __init__(
        self,
        cache_dir: Path,
        log: LogFn | None = None,
        roots: list[Path] | None = None,
        max_exes: int | None = None,
        enable_cache: bool = True,
        progress: ProgressFn | None = None,
    ):
        self.cache_dir = cache_dir
        self.log = log or (lambda _tag, _msg: None)
        self.roots = roots
        self.max_exes = max_exes
        self.cache = ExeAnalysisCache(cache_dir) if enable_cache else None
        self.progress = progress

    def scan(self) -> ExeScanSummary:
        started = time.monotonic()
        discovery = ExeDiscovery(log=self.log, roots=self.roots, max_exes=self.max_exes)
        paths, stats = discovery.discover()
        summary = ExeScanSummary(stats=stats)
        total = len(paths)
        self.log("EXE-DISCOVERY", f"EXE inventory found: {total}")
        db = ExeArtifactDatabase(self.cache_dir)
        for index, path in enumerate(paths, 1):
            if self.progress:
                self.progress(index - 1, total, f"exe {index}/{total} | analyzing: {path.name}")
            self.log("EXE-SCAN", f"{index}/{total} analyzing {path.name}")
            result = self.analyze_file(path, newly_seen=not db.has_seen_path(path))
            summary.results.append(result)
            if result.cache_reused:
                summary.cache_hits += 1
                self.log("EXE-CACHE", f"reused analysis: {result.file_name}")
            else:
                summary.cache_misses += 1
            if result.verdict in {"REVIEW", "HIGH_REVIEW", "CRITICAL_REVIEW"}:
                self.log("EXE-REVIEW", f"{result.verdict}: {result.file_name} | {result.risk_score}/100")
            elif result.signature.status == "SIGNED_VALID":
                self.log("EXE-OK", f"signed application: {result.file_name}")
        if self.progress and total:
            self.progress(total, total, "exe analysis complete")
        self._mark_duplicate_hashes(summary.results)
        diff = db.compare_previous(summary.results)
        summary.new_since_last_scan = int(diff["new"])
        summary.changed_since_last_scan = int(diff["changed"])
        summary.same_hash_different_path = int(diff["same_hash_different_path"])
        summary.important_changes = list(diff["important"])
        db.update(summary.results)
        db.save()
        if self.cache:
            self.cache.save()
        summary.duplicate_hashes = sum(1 for item in summary.results if item.duplicate_status)
        summary.elapsed_seconds = round(time.monotonic() - started, 2)
        return summary

    def analyze_file(self, path: Path, newly_seen: bool = False, file_type: str | None = None) -> ExeScanResult:
        try:
            stat = path.stat()
        except OSError as exc:
            return ExeScanResult(
            path=path,
            file_name=path.name,
            size_bytes=0,
            created_time=dt.datetime.fromtimestamp(0),
            last_modified=dt.datetime.fromtimestamp(0),
            file_type=file_type or "PE_EXE",
            error=str(exc),
                risk_score=45,
                verdict="REVIEW",
                reasons=[f"could not read executable metadata: {exc}"],
                evidence=["file metadata read failed"],
            )
        created = dt.datetime.fromtimestamp(getattr(stat, "st_ctime", stat.st_mtime)).replace(microsecond=0)
        modified = dt.datetime.fromtimestamp(stat.st_mtime).replace(microsecond=0)
        try:
            digest = sha256_file(path)
        except OSError as exc:
            digest = ""
            result = ExeScanResult(
                path=path,
                file_name=path.name,
                size_bytes=stat.st_size,
                created_time=created,
                last_modified=modified,
                file_type=file_type or "PE_EXE",
                error=str(exc),
            )
            score_exe(result)
            return result
        if self.cache:
            cached = self.cache.get(path, digest, stat.st_size, modified)
            if cached:
                cached.file_type = file_type or cached.file_type
                cached.folder_category = classify_folder(path)
                cached.review_priority, cached.review_priority_reason = review_priority(cached, newly_seen=newly_seen)
                return cached
        result = ExeScanResult(
            path=path,
            file_name=path.name,
            size_bytes=stat.st_size,
            created_time=created,
            last_modified=modified,
            sha256=digest,
            file_type=file_type or "PE_EXE",
            folder_category=classify_folder(path),
            analysis_mode="HEADER_ONLY" if file_type == "PE_SYS" else ("LIMITED" if stat.st_size > LARGE_EXE_BYTES else "FULL"),
        )
        self.log("EXE-PE", "reading headers")
        result.pe = parse_pe(path, max_string_bytes=MAX_STRING_SCAN_BYTES)
        self.log("EXE-SIGN", "checking signature")
        result.signature = check_signature(path, include_details=False)
        if result.analysis_mode != "HEADER_ONLY":
            self._collect_strings(result)
        result.import_categories = import_categories(result.pe.imported_dlls, result.pe.imported_functions)
        apply_identity_context(result)
        result.review_priority, result.review_priority_reason = review_priority(result, newly_seen=newly_seen)
        self._fingerprint(result)
        self.log("EXE-SCORE", "calculating review score")
        score_exe(result)
        result.confidence = _confidence(result)
        if self.cache:
            self.cache.put(result)
        return result

    def _collect_strings(self, result: ExeScanResult) -> None:
        try:
            with result.path.open("rb") as fh:
                data = fh.read(MAX_STRING_SCAN_BYTES)
        except OSError as exc:
            result.error = result.error or str(exc)
            return
        strings = extract_pe_strings(data, limit=5000)
        categories, evidence = classify_strings(strings)
        result.string_categories = categories
        result.string_evidence = evidence[:5]
        result.evidence.extend(evidence[:2])

    def _fingerprint(self, result: ExeScanResult) -> None:
        entropy_buckets = []
        for section in result.pe.sections:
            if section.entropy >= 7.2:
                entropy_buckets.append("high")
            elif section.entropy >= 5.5:
                entropy_buckets.append("mid")
            else:
                entropy_buckets.append("low")
        size_bucket = _size_bucket(result.size_bytes)
        tokens = {
            "machine": result.pe.machine_type,
            "subsystem": result.pe.subsystem,
            "sections": ",".join(section.name.lower() for section in result.pe.sections),
            "entropy": ",".join(entropy_buckets),
            "dlls": ",".join(sorted(result.pe.imported_dlls)[:50]),
            "categories": ",".join(sorted(result.import_categories)),
            "resource": f"icon={result.pe.icon_present};manifest={result.pe.manifest_present}",
            "version": "|".join(sorted(result.pe.version_info.values())[:8]),
            "signer": result.signature.signer_subject,
            "overlay": "yes" if result.pe.overlay_size else "no",
            "size": size_bucket,
        }
        payload = json.dumps(tokens, sort_keys=True)
        result.structural_fingerprint = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:24]
        result.structural_summary = f"{result.pe.architecture}/{result.pe.subsystem}; sections={len(result.pe.sections)}; imports={len(result.pe.imported_dlls)}; size={size_bucket}"

    def _mark_duplicate_hashes(self, results: list[ExeScanResult]) -> None:
        by_hash: dict[str, list[ExeScanResult]] = defaultdict(list)
        for result in results:
            if result.sha256:
                by_hash[result.sha256.lower()].append(result)
        for group in by_hash.values():
            if len(group) <= 1:
                continue
            paths = [str(item.path) for item in group]
            for item in group:
                item.duplicate_status = item.duplicate_status or "duplicate_hash_current_scan"
                item.duplicate_paths = [path for path in paths if path != str(item.path)][:4]

    def finalize_results(self, results: list[ExeScanResult], stats=None) -> ExeScanSummary:
        summary = ExeScanSummary(results=results)
        if stats is not None:
            summary.stats = stats
        summary.cache_hits = sum(1 for item in results if item.cache_reused)
        summary.cache_misses = max(0, len(results) - summary.cache_hits)
        self._mark_duplicate_hashes(summary.results)
        db = ExeArtifactDatabase(self.cache_dir)
        diff = db.compare_previous(summary.results)
        summary.new_since_last_scan = int(diff["new"])
        summary.changed_since_last_scan = int(diff["changed"])
        summary.same_hash_different_path = int(diff["same_hash_different_path"])
        summary.important_changes = list(diff["important"])
        db.update(summary.results)
        db.save()
        if self.cache:
            self.cache.save()
        summary.duplicate_hashes = sum(1 for item in summary.results if item.duplicate_status)
        return summary


def _size_bucket(size: int) -> str:
    if size < 512 * 1024:
        return "tiny"
    if size < 5 * 1024 * 1024:
        return "small"
    if size < 50 * 1024 * 1024:
        return "medium"
    if size < 200 * 1024 * 1024:
        return "large"
    return "huge"


def _confidence(result: ExeScanResult) -> str:
    score = 25
    if result.pe.mz_header and result.pe.pe_signature:
        score += 20
    if result.sha256:
        score += 10
    if result.signature.status != "UNKNOWN":
        score += 12
    if result.pe.sections:
        score += 12
    if result.pe.imported_dlls or result.pe.version_info:
        score += 12
    if result.analysis_mode in {"LIMITED", "HEADER_ONLY"}:
        score -= 12
    if result.error:
        score -= 20
    if score >= 70:
        return "HIGH"
    if score >= 42:
        return "MEDIUM"
    return "LOW"
