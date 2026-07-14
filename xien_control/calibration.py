from __future__ import annotations

import json
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .jar_scanner import JarScanner
from .models import JarScanResult, LauncherLocation


VERDICT_RANK = {"CLEAN": 0, "LOW_SIGNAL": 1, "SUSPICIOUS": 2, "HIGH_RISK": 3, "CRITICAL": 4}


@dataclass
class CalibrationOutcome:
    name: str
    expected: str
    actual: str
    score: int
    confidence: str
    passed: bool
    top_reason: str


def load_cases(fixtures_dir: Path) -> tuple[list[dict], dict[str, dict]]:
    cases = json.loads((fixtures_dir / "calibration_cases.json").read_text(encoding="utf-8"))
    expected = json.loads((fixtures_dir / "expected_result.json").read_text(encoding="utf-8"))
    return list(cases), dict(expected)


def build_fixture_jar(case: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / str(case["filename"])
    with zipfile.ZipFile(path, "w") as jar:
        metadata = case.get("metadata")
        if metadata:
            jar.writestr("fabric.mod.json", json.dumps(metadata))
        for resource_path, text in case.get("resources", {}).items():
            jar.writestr(resource_path, text)
        for class_spec in case.get("classes", []):
            jar.writestr(class_spec["path"], _class_bytes(*class_spec.get("strings", [])))
    return path


def run_calibration(fixtures_dir: Path, work_dir: Path | None = None) -> list[CalibrationOutcome]:
    cases, expected = load_cases(fixtures_dir)
    owned_temp: tempfile.TemporaryDirectory[str] | None = None
    if work_dir is None:
        owned_temp = tempfile.TemporaryDirectory(prefix="xien-calibration-")
        work_dir = Path(owned_temp.name)
    try:
        scanner = JarScanner(cache_dir=work_dir / "cache", enable_cache=False)
        location = LauncherLocation("Calibration", "fixtures", work_dir, "test")
        outcomes: list[CalibrationOutcome] = []
        for case in cases:
            jar_path = build_fixture_jar(case, work_dir / "jars")
            result = scanner.scan(jar_path, location)
            spec = expected.get(case["name"], {})
            passed = _matches_expected(result, spec)
            outcomes.append(
                CalibrationOutcome(
                    name=case["name"],
                    expected=_expected_label(spec),
                    actual=result.verdict,
                    score=result.risk_score,
                    confidence=result.analysis_confidence,
                    passed=passed,
                    top_reason=(result.risk_reasons or result.why_flagged or [""])[0],
                )
            )
        return outcomes
    finally:
        if owned_temp is not None:
            owned_temp.cleanup()


def _matches_expected(result: JarScanResult, spec: dict) -> bool:
    min_v = spec.get("min_verdict")
    max_v = spec.get("max_verdict")
    if min_v and VERDICT_RANK[result.verdict] < VERDICT_RANK[min_v]:
        return False
    if max_v and VERDICT_RANK[result.verdict] > VERDICT_RANK[max_v]:
        return False
    for evidence in spec.get("important_evidence", []):
        if not any(match.rule_id == evidence or evidence.lower() in match.evidence_preview.lower() for match in result.detections):
            return False
    expected_conf = spec.get("confidence")
    if expected_conf and result.analysis_confidence != expected_conf:
        return False
    expected_reachability = spec.get("feature_reachability")
    if expected_reachability and result.feature_reachability != expected_reachability:
        return False
    return True


def _expected_label(spec: dict) -> str:
    if spec.get("min_verdict") and spec.get("max_verdict"):
        return f"{spec['min_verdict']}..{spec['max_verdict']}"
    return str(spec.get("min_verdict") or spec.get("max_verdict") or "?")


def _class_bytes(*utf8_values: str) -> bytes:
    constants = []
    for value in utf8_values:
        encoded = str(value).encode("utf-8")
        constants.append(b"\x01" + len(encoded).to_bytes(2, "big") + encoded)
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + (len(constants) + 1).to_bytes(2, "big") + b"".join(constants)
