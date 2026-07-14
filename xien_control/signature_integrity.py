from __future__ import annotations

import zipfile

from .models import JarScanResult


def analyze_signature_integrity(zf: zipfile.ZipFile, result: JarScanResult) -> None:
    names = [info.filename.replace("\\", "/") for info in zf.infolist()]
    lower = [name.lower() for name in names]
    sig_files = [name for name in lower if name.startswith("meta-inf/") and name.endswith((".sf", ".rsa", ".dsa"))]
    manifest = "meta-inf/manifest.mf" in lower
    if not sig_files:
        result.signature_status = "UNSIGNED"
        return
    if not manifest or not any(name.endswith(".sf") for name in sig_files):
        result.signature_status = "SIGNATURE_METADATA_INCOMPLETE"
        result.zip_anomalies.append("signature metadata incomplete")
        return
    result.signature_status = "SIGNED_PRESENT"
