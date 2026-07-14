from __future__ import annotations

import re
import zipfile
from xml.etree import ElementTree

from .confidence import assign_confidence
from .pe_signature import check_signature
from .priority import assign_priority
from .static_models import FileInventoryItem, StaticAnalysisResult
from .utils import sha256_file


class InstallerAnalyzer:
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
        except OSError as exc:
            result.error = str(exc)
        signature = check_signature(item.path, include_details=False)
        score = 0
        reasons: list[str] = []
        if signature.status in {"UNSIGNED", "UNKNOWN"} and item.folder_category in {"USER_DOWNLOADS", "USER_DESKTOP", "TEMP", "APPDATA_LOCAL", "APPDATA_ROAMING"}:
            score += 22
            reasons.append("unsigned installer in user folder")
            result.evidence.append(f"signature status: {signature.status}")
        if item.file_type in {"INSTALLER_MSIX", "INSTALLER_APPX", "INSTALLER_APPXBUNDLE", "INSTALLER_MSIXBUNDLE"}:
            self._analyze_appx_manifest(result)
        else:
            self._analyze_msi_strings(result)
        if result.evidence:
            score += min(18, len(result.evidence) * 6)
        result.risk_score = min(100, score)
        result.verdict = _verdict(score)
        result.reasons = reasons or ["installer metadata has no strong review signals"]
        assign_confidence(result, sources=3 if result.evidence else 2)
        assign_priority(result)
        return result

    def _analyze_appx_manifest(self, result: StaticAnalysisResult) -> None:
        try:
            with zipfile.ZipFile(result.path) as zf:
                names = zf.namelist()
                manifest_name = next((name for name in names if name.lower().endswith("appxmanifest.xml")), "")
                if not manifest_name:
                    result.evidence.append("AppxManifest.xml missing")
                    return
                text = zf.read(manifest_name).decode("utf-8", errors="replace")
        except (OSError, zipfile.BadZipFile, KeyError):
            result.error = result.error or "installer archive could not be read"
            return
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError:
            result.evidence.append("AppxManifest.xml parse failed")
            return
        identity = root.find(".//{*}Identity")
        if identity is not None:
            name = identity.attrib.get("Name", "")
            publisher = identity.attrib.get("Publisher", "")
            version = identity.attrib.get("Version", "")
            if name:
                result.evidence.append(f"package identity: {name}")
            if publisher:
                result.evidence.append(f"publisher: {publisher[:80]}")
            if version:
                result.evidence.append(f"version: {version}")
        capabilities = [node.attrib.get("Name", "") for node in root.findall(".//{*}Capability")]
        if capabilities:
            result.evidence.append("capabilities: " + ", ".join(capabilities[:4]))

    def _analyze_msi_strings(self, result: StaticAnalysisResult) -> None:
        try:
            data = result.path.read_bytes()[:512 * 1024]
        except OSError:
            return
        text = data.decode("utf-8", errors="ignore") + "\n" + data.decode("utf-16le", errors="ignore")
        for label, pattern in (
            ("product", r"ProductName[^\w]{0,8}([A-Za-z0-9 ._-]{3,80})"),
            ("manufacturer", r"Manufacturer[^\w]{0,8}([A-Za-z0-9 ._-]{3,80})"),
            ("version", r"ProductVersion[^\w]{0,8}([0-9]+(?:\.[0-9]+){1,3})"),
        ):
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                result.evidence.append(f"{label}: {match.group(1).strip()}")


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
