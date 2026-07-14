from __future__ import annotations

from pathlib import Path

from xien_control.calibration import run_calibration


def test_calibration_fixture_dataset(tmp_path):
    fixtures = Path(__file__).parent / "fixtures"

    outcomes = run_calibration(fixtures, tmp_path)

    assert outcomes
    assert all(outcome.passed for outcome in outcomes), [
        (outcome.name, outcome.expected, outcome.actual, outcome.score, outcome.top_reason)
        for outcome in outcomes
        if not outcome.passed
    ]
