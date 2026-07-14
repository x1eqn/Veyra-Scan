from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from xien_control.calibration import run_calibration  # noqa: E402


def main() -> int:
    fixtures = ROOT / "tests" / "fixtures"
    outcomes = run_calibration(fixtures)
    headers = ("fixture", "expected", "actual", "score", "confidence", "passed", "top reason")
    widths = [34, 24, 14, 8, 13, 9, 60]
    print(_row(headers, widths))
    print("-" * sum(widths))
    failed = 0
    for outcome in outcomes:
        if not outcome.passed:
            failed += 1
        print(
            _row(
                (
                    outcome.name,
                    outcome.expected,
                    outcome.actual,
                    str(outcome.score),
                    outcome.confidence,
                    "yes" if outcome.passed else "no",
                    outcome.top_reason[:50],
                ),
                widths,
            )
        )
    return 1 if failed else 0


def _row(values, widths) -> str:
    return "".join(str(value).ljust(width) for value, width in zip(values, widths))


if __name__ == "__main__":
    raise SystemExit(main())
