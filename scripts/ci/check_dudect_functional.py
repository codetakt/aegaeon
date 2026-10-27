"""Build and exercise every Dudect callback without collecting timing samples."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/constant_time"))
from dudect_package import checked_package  # noqa: E402
from run_candidate import current_sources  # noqa: E402


def check_receipt(text: str, expected: list[str]) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in text.splitlines()]
    wanted = [{"case_id": name, "self_test": True, "timing_executed": False} for name in expected]
    if rows != wanted:
        raise ValueError("Non-timing callback receipts do not match the complete case inventory")
    # JSON booleans must not be substituted with integers.
    if any(
        type(row["self_test"]) is not bool or type(row["timing_executed"]) is not bool
        for row in rows
    ):
        raise ValueError("Invalid self-test receipt types")
    return rows


def run(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "kind": "dudect-functional-check/1",
        "complete": False,
        "timing_executed": False,
        "timing_qualification": "not_evaluated",
        "cases": [],
    }
    try:
        for suite in ("legacy", "nix"):
            package = output / suite
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tests/constant_time/run_contract.py"),
                    "--suite",
                    suite,
                    "--build-package",
                    str(package),
                ],
                check=True,
                timeout=600,
            )
            index = checked_package(package, current_sources(ROOT), suite)
            for entry in index["executables"]:
                result = subprocess.run(
                    [str(package / entry["relative_binary"]), "--self-test"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                (package / (entry["name"] + ".stdout")).write_text(result.stdout)
                (package / (entry["name"] + ".stderr")).write_text(result.stderr)
                result.check_returncode()
                rows = check_receipt(result.stdout, [f"{suite}/{n}" for n in entry["cases"]])
                report["cases"].extend(rows)
        if len(report["cases"]) != 21:
            raise ValueError("Expected all 21 callback cases")
        report["complete"] = True
    finally:
        (output / "functional-report.json").write_text(json.dumps(report, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    run(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
