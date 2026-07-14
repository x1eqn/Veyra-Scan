from __future__ import annotations

from .exe_models import ExeScanResult


VERDICT_THRESHOLDS = (
    (90, "CRITICAL_REVIEW"),
    (70, "HIGH_REVIEW"),
    (45, "REVIEW"),
    (20, "LOW_SIGNAL"),
    (0, "CLEAN"),
)


def verdict_for_exe_score(score: int) -> str:
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return "CLEAN"


def score_exe(result: ExeScanResult) -> None:
    score = 0
    reasons: list[str] = []
    folder = result.folder_category
    unsigned = result.signature.status in {"UNSIGNED", "UNKNOWN"}
    sensitive_user_folder = folder in {"USER_DOWNLOADS", "USER_DESKTOP", "USER_DOCUMENTS", "APPDATA_LOCAL", "APPDATA_ROAMING", "TEMP", "STARTUP", "UNKNOWN_USER_FOLDER"}

    if result.error:
        score += 20
        reasons.append("file could not be fully analyzed")
    if result.signature.status == "SIGNED_INVALID":
        score += 35
        reasons.append("invalid Authenticode signature")
    if unsigned and sensitive_user_folder:
        score += 30
        reasons.append(f"unsigned executable in {folder.replace('_', ' ').title()}")
    elif unsigned:
        score += 12
        reasons.append("no valid Authenticode signature")
    if folder == "STARTUP" and unsigned:
        score += 24
        reasons.append("startup location increases review priority")
    elif folder in {"TEMP", "APPDATA_LOCAL", "APPDATA_ROAMING"} and unsigned:
        score += 14
        reasons.append("user-writable AppData/Temp location")

    if result.metadata_empty and unsigned and sensitive_user_folder:
        score += 14
        reasons.append("empty version info in user folder")
    elif result.metadata_empty:
        score += 4
    if result.identity_mismatch:
        score += 16
        reasons.append("filename and version identity metadata do not match")
    if result.file_type == "PE_SCR" and sensitive_user_folder:
        score += 18
        reasons.append("screensaver executable in user folder")
    if result.file_type in {"PE_DLL", "PE_CPL", "PE_OCX"} and unsigned and folder in {"APPDATA_LOCAL", "APPDATA_ROAMING", "TEMP", "UNKNOWN_USER_FOLDER"}:
        score += 14
        reasons.append(f"unsigned {result.file_type.replace('PE_', '')} in user-writable folder")
    if result.file_type == "PE_SYS":
        score = max(0, score - 8)
        reasons.append("driver file was treated as header/metadata review only")

    high_entropy = result.pe.high_entropy_sections
    if high_entropy:
        score += 12
        names = ", ".join(section.name for section in high_entropy[:2])
        result.evidence.append(f"high-entropy section {names} ({high_entropy[0].entropy})")
        reasons.append("high-entropy PE section")
    if result.pe.executable_writable_sections:
        score += 10
        result.evidence.append("executable+writable section: " + ", ".join(section.name for section in result.pe.executable_writable_sections[:2]))
        reasons.append("executable and writable PE section")
    if result.pe.unusual_sections:
        score += 6
        result.evidence.append("unusual section names: " + ", ".join(section.name for section in result.pe.unusual_sections[:3]))
    if result.pe.overlay_size > max(4 * 1024 * 1024, result.size_bytes * 0.25):
        score += 10
        result.evidence.append(f"large overlay data: {result.pe.overlay_size} bytes")
        reasons.append("large overlay data")
    if result.pe.import_count <= 2 and high_entropy and result.pe.pe_signature:
        score += 14
        reasons.append("low import count combined with high entropy")
        result.evidence.append("very low import count with high entropy")

    strong_imports = result.import_categories.intersection({"networking", "registry", "process_control", "service_control", "crypto"})
    if unsigned and sensitive_user_folder and len(strong_imports) >= 2:
        score += 10
        result.evidence.append("import categories: " + ", ".join(sorted(strong_imports)[:4]))
        reasons.append("sensitive import categories in unsigned user-folder executable")
    if result.string_categories.get("command_like", 0) and unsigned and sensitive_user_folder:
        score += 8
        reasons.append("command-like strings in unsigned user-folder executable")
    if result.string_categories.get("url_like", 0) and result.string_categories.get("registry_like", 0) and unsigned and sensitive_user_folder:
        score += 8
        reasons.append("URL and registry-like strings appear together")
    if result.pe.tls_callbacks_present and unsigned and sensitive_user_folder:
        score += 10
        reasons.append("TLS callback context in unsigned user-folder executable")
        result.evidence.append("TLS callbacks present")
    if result.pe.package_type and unsigned and sensitive_user_folder:
        score += 8
        reasons.append("unsigned bundled/packed executable in user folder")
        result.evidence.append(f"detected package type: {result.pe.package_type}")
    if result.pe.dotnet_metadata_present and unsigned and sensitive_user_folder:
        score += 6
        reasons.append("unsigned user-folder .NET assembly")
        if result.pe.dotnet_assembly_name and result.pe.dotnet_assembly_name.lower() not in result.file_name.lower():
            score += 8
            result.evidence.append(f".NET assembly name differs: {result.pe.dotnet_assembly_name}")
    if result.pe.pdb_path and result.company_name and result.company_name.lower() not in result.pe.pdb_path.lower():
        score += 5
        result.evidence.append("debug PDB path does not match product identity")

    if result.signature.status == "SIGNED_VALID" and result.trusted_vendor and folder == "SYSTEM_WINDOWS":
        score -= 45
        reasons.append("valid trusted vendor signature in Windows system path")
    elif result.signature.status == "SIGNED_VALID" and result.trusted_vendor and folder == "PROGRAM_FILES":
        score -= 35
        reasons.append("valid trusted vendor signature in Program Files")
    elif result.signature.status == "SIGNED_VALID" and result.trusted_vendor:
        score -= 22
        reasons.append("valid trusted vendor signature")
    elif result.signature.status == "SIGNED_VALID":
        score -= 12
        reasons.append("valid Authenticode signature")

    if folder == "PROGRAM_FILES" and result.signature.status == "SIGNED_VALID":
        score -= 8
    if folder == "SYSTEM_WINDOWS" and result.signature.status == "SIGNED_VALID":
        score -= 12

    score = max(0, min(100, score))
    result.risk_score = score
    result.verdict = verdict_for_exe_score(score)
    result.reasons = _reason_summary(result, reasons)
    if not result.evidence:
        _default_evidence(result)
    result.evidence = _unique(result.evidence)[:5]


def _reason_summary(result: ExeScanResult, reasons: list[str]) -> list[str]:
    if not reasons:
        return ["no strong review indicators"]
    if result.verdict in {"HIGH_REVIEW", "CRITICAL_REVIEW"}:
        return _unique(reasons)[:3]
    return _unique(reasons)[:2]


def _default_evidence(result: ExeScanResult) -> None:
    if result.signature.status:
        result.evidence.append(f"signature status: {result.signature.status}")
    if result.folder_category:
        result.evidence.append(f"folder category: {result.folder_category}")
    if result.import_categories:
        result.evidence.append("import categories: " + ", ".join(sorted(result.import_categories)[:4]))


def _unique(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        clean = " ".join(str(value).split())
        key = clean.lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(clean)
    return out
