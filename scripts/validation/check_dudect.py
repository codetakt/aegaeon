#!/usr/bin/env python3
"""Validate complete source-bound per-case timing evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/constant_time"))
from run_contract import validate_report_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report", nargs="?", type=Path, default=Path("artifacts/ct/dudect/report.json")
    )
    args = parser.parse_args()
    try:
        validate_report_file(Path(__file__).resolve().parents[2], args.report.resolve())
    except (OSError, ValueError) as error:
        print(f"Dudect evidence rejected: {error}", file=sys.stderr)
        return 1
    print(
        "Dudect: complete per-case observation contract satisfied; "
        "product assurance not established"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
