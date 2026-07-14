from __future__ import annotations

import zipfile
from pathlib import Path

from .confidence import assign_confidence
from .file_classifier import classify_file
from .priority import assign_priority
from .static_models import FileInventoryItem, StaticAnalysisResult
from .utils import sha256_file


APPLICATION_TYPES = {
    "JAVA_ARCHIVE",
    "PE_EXE",
    "PE_DLL",
    "PE_SCR",
    "PE_CPL",
    "PE_SYS",
    "PE_OCX",
    "SCRIPT_BAT",
    "SCRIPT_CMD",
    "SCRIPT_PS1",
    "SCRIPT_VBS",
    "SCRIPT_JS",
    "SCRIPT_WSF",
    "INSTALLER_MSI",
    "INSTALLER_MSIX",
    "INSTALLER_APPX",
    "INSTALLER_APPXBUNDLE",
    "INSTALLER_MSIXBUNDLE",
}


class ArchiveScanner:
    def analyze(self, item: FileInventoryItem) -> StaticAnalysisResult:
        result = StaticAnalysisResult(
            path=item.path,
            file_name=item.file_name,
            file_type=item.file_type,
            size_bytes=item.size_bytes,
            last_modified=item.last_modified,
            folder_category=item.folder_category,
        )
        try:
            result.sha256 = sha256_file(item.path)
        except OSError:
            result.sha256 = ""
        if item.file_type != "ARCHIVE_ZIP":
            result.verdict = "LOW_SIGNAL" if item.folder_category in {"USER_DOWNLOADS", "USER_DESKTOP", "TEMP"} else "CLEAN"
            result.reasons.append("optional archive format inventory only")
            result.evidence.append("archive listing not supported without optional parser")
            assign_confidence(result, sources=1, partial=True)
            assign_priority(result)
            return result
        try:
            with zipfile.ZipFile(item.path) as zf:
                infos = zf.infolist()
        except zipfile.BadZipFile:
            result.error = "invalid zip archive"
            result.verdict = "LOW_SIGNAL"
            result.risk_score = 20
            result.reasons.append("invalid archive")
            assign_confidence(result, sources=1, partial=True)
            assign_priority(result)
            return result
        except OSError as exc:
            result.error = str(exc)
            result.verdict = "REVIEW"
            result.risk_score = 45
            result.reasons.append("archive could not be read")
            assign_confidence(result, sources=1, partial=True)
            assign_priority(result)
            return result
        nested = []
        for info in infos[:4000]:
            nested_type = classify_file(Path(info.filename))
            if nested_type in APPLICATION_TYPES:
                nested.append(f"{info.filename} ({nested_type}, {info.file_size} bytes)")
        result.nested_items = nested[:20]
        score = 0
        if nested:
            score += 24
            result.reasons.append("archive contains application/script files")
            result.evidence.append("nested item: " + nested[0])
            if item.folder_category in {"USER_DOWNLOADS", "USER_DESKTOP", "TEMP", "APPDATA_LOCAL", "APPDATA_ROAMING"}:
                score += 22
                result.reasons.append("archive is in user folder")
        result.risk_score = min(100, score)
        result.verdict = _verdict(score)
        if not result.reasons:
            result.reasons.append("archive has no application review items")
        assign_confidence(result, sources=2 if nested else 1)
        assign_priority(result, archive_nested=bool(nested))
        return result


def _verdict(score: int) -> str:
    if score >= 90:
        return "CRITICAL_REVIEW"
    if score >= 70:
        return "HIGH_REVIEW"
    if score >= 45:
        return "REVIEW"
    if score >= 20:
        return "LOW_SIGNAL"
    return "CLEAN"
