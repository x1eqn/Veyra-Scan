from __future__ import annotations

import datetime as dt
import posixpath
import zipfile

from .models import JarScanResult


def analyze_zip_structure(zf: zipfile.ZipFile, result: JarScanResult) -> None:
    seen: set[str] = set()
    normalized_seen: set[str] = set()
    now_year = dt.datetime.now().year
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        lower = name.lower()
        if lower in seen:
            result.zip_anomalies.append(f"duplicate entry: {name[:80]}")
        seen.add(lower)
        normalized = posixpath.normpath(lower)
        if normalized in normalized_seen and normalized != lower:
            result.zip_anomalies.append(f"path normalization collision: {name[:80]}")
        normalized_seen.add(normalized)
        if len(name) > 220:
            result.zip_anomalies.append(f"very long entry path: {name[:80]}")
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}:
            result.zip_anomalies.append(f"non-standard compression method: {name[:80]}")
        if info.compress_size and info.file_size / max(1, info.compress_size) > 120:
            result.zip_anomalies.append(f"very high compression ratio: {name[:80]}")
        year = info.date_time[0]
        if year < 1995 or year > now_year + 1:
            result.zip_anomalies.append(f"unusual entry timestamp: {name[:80]}")
        if len(result.zip_anomalies) >= 12:
            break
