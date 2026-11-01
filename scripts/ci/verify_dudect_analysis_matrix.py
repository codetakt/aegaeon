"""Replay a pinned research evidence matrix; never launch native timing or admit CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

PLAN_SCHEMA = "dudect-analysis-replay-matrix/1"
REPORT_KIND = "dudect-enclosed-calibration-research-gate/1"
CELLS = {(compiler, suite) for compiler in ("gcc", "clang") for suite in ("legacy", "nix")}


def require(condition: bool, message: str) -> None:  # noqa: FBT001 -- assertion predicate
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), f"Expected JSON object: {path}")
    return dict(value)


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def identifier(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9_-]+", value) is not None


def store_path(value: str) -> Path:
    require(
        re.fullmatch(r"/nix/store/[a-z0-9]{32}-[a-zA-Z0-9._+-]+", value) is not None,
        "Expected an explicit immutable Nix package path",
    )
    return Path(value)


def check_matrix(plan: dict[str, Any]) -> None:
    require(plan["schema"] == PLAN_SCHEMA and plan["adopted"] is False, "Wrong replay plan")
    require(plan["mode"] == "distributed", "This matrix requires the distributed PR candidate")
    cycles = plan["cycles"]
    require(bool(cycles) and all(identifier(c) for c in cycles), "Invalid cycle inventory")
    require(len(cycles) == len(set(cycles)), "Duplicate cycle")
    units = plan["units"]
    require(all(identifier(u["id"]) for u in units), "Invalid unit identifier")
    require(len({u["id"] for u in units}) == len(units), "Duplicate unit")
    cells = [(u["cycle"], u["compiler"], u["suite"]) for u in units]
    expected = {(c, compiler, suite) for c in cycles for compiler, suite in CELLS}
    require(
        len(cells) == len(expected) and set(cells) == expected, "Incomplete or duplicate matrix"
    )
    require(
        set(plan["native_packages"]) == {f"{c}-{s}" for c, s in CELLS},
        "Expected four compiler/suite packages",
    )
    require(
        len({p["path"] for p in plan["native_packages"].values()}) == 4,
        "Compiler/suite packages must be distinct",
    )


def pinned_inputs(plan: dict[str, Any]) -> tuple[Path, dict[str, dict[str, Any]]]:
    package = store_path(plan["analysis_package"]["path"])
    command = package / "bin/dudect-analysis"
    require(sha256(command) == plan["analysis_package"]["executable_sha256"], "Verifier changed")
    contract = (
        package
        / "libexec/dudect-analysis/source/tests/constant_time/contracts"
        / "case-contract-candidate.json"
    )
    require(sha256(contract) == plan["case_contract_sha256"], "Case contract changed")
    cases = read_json(contract)["cases"]
    indexes = {}
    for cell, pin in plan["native_packages"].items():
        path = store_path(pin["path"]) / "package.json"
        require(sha256(path) == pin["index_sha256"], "Native package index changed")
        index = read_json(path)
        suite = cell.split("-")[1]
        require(index["suite"] == suite, "Native package suite differs")
        require(index["contract_sha256"] == plan["case_contract_sha256"], "Native contract differs")
        actual = [f"{suite}/{n}" for e in index["executables"] for n in e["cases"]]
        expected = [c["stable_id"] for c in cases if c["stable_id"].split("/")[0] == suite]
        require(
            len(actual) == len(expected) and set(actual) == set(expected),
            "Native case coverage differs",
        )
        require(len(expected) == (11 if suite == "legacy" else 10), "Expected all 21 cases")
        indexes[cell] = index
    return command, indexes


def check_report(report: dict[str, Any], unit: dict[str, Any], index: dict[str, Any]) -> None:
    require(
        report["kind"] == REPORT_KIND and report["adopted"] is False,
        "Expected a research report, not an adopted gate result",
    )
    require(report["profile"] == "pr" and report["suite"] == unit["suite"], "Wrong suite/profile")
    require(report["analysis"] == unit["analysis"], "Analysis identity or split domain differs")
    require(report["native_package"] == index, "Wrong compiler/native package")
    expected = [f"{unit['suite']}/{n}" for e in index["executables"] for n in e["cases"]]
    rows = report["assessment"]
    require([r["case_id"] for r in rows] == expected, "Missing, reordered or duplicate case")
    require(all(type(r["requirement_satisfied"]) is bool for r in rows), "Invalid role outcome")
    require(type(report["gate_satisfied"]) is bool, "Invalid gate outcome")
    require(
        report["gate_satisfied"] == all(r["requirement_satisfied"] for r in rows),
        "Gate outcome disagrees with role outcomes",
    )


def verify_unit(
    command: Path, evidence: Path, output: Path, unit: dict[str, Any], index: dict[str, Any]
) -> dict[str, Any]:
    gate = evidence / unit["id"] / "gate"
    path = gate / "research-report.json"
    require(not (gate / "execution-failure.json").exists(), "Execution failure retained")
    before = sha256(path)
    report = read_json(path)
    check_report(report, unit, index)
    with (output / f"{unit['id']}.log").open("wb") as log:
        result = subprocess.run(
            [str(command), "--output", str(gate), "--verify-only"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=900,
            check=False,
        )
    require(sha256(path) == before, "Report changed during verification")
    expected_exit = 0 if report["gate_satisfied"] else 1
    require(result.returncode == expected_exit, "Full evidence replay failed")
    # Exit 1 can also mean a replay exception. The packaged verifier emits its
    # traceback in that case; a completed statistical failure has empty output.
    require((output / f"{unit['id']}.log").stat().st_size == 0, "Unexpected verifier output")
    return {
        "id": unit["id"],
        "cycle": unit["cycle"],
        "compiler": unit["compiler"],
        "suite": unit["suite"],
        "evidence": str(gate),
        "report_sha256": before,
        "evidence_verified": True,
        "requirement_satisfied": report["gate_satisfied"],
        "assessment": report["assessment"],
    }


def check_analysis(plan: dict[str, Any]) -> None:
    common = None
    for unit in plan["units"]:
        analysis = unit["analysis"]
        require(
            analysis["packet"] == plan["packet"] and analysis["unit"] == unit["id"],
            "Wrong frozen split identifiers",
        )
        require(
            analysis["mode"] == plan["mode"] and analysis["adopted"] is False, "Wrong analysis mode"
        )
        current = {k: v for k, v in analysis.items() if k not in {"packet", "unit"}}
        if common is None:
            common = current
        require(current == common, "Mixed analysis implementation or policy")


def aggregate(plan: dict[str, Any], evidence: Path, output: Path) -> dict[str, Any]:
    check_matrix(plan)
    check_analysis(plan)
    command, indexes = pinned_inputs(plan)
    records: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "schema": "dudect-analysis-matrix-verification/1",
        "adopted": False,
        "ci_admission": False,
        "fresh_measurements": False,
        "environment_admission": "not_assessed",
        "verification_complete": False,
        "research_requirements_satisfied": False,
        "units": records,
    }
    write_json(output / "summary.json", summary)
    for unit in plan["units"]:
        try:
            record = verify_unit(
                command, evidence, output, unit, indexes[f"{unit['compiler']}-{unit['suite']}"]
            )
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
            record = {
                "id": unit["id"],
                "evidence_verified": False,
                "requirement_satisfied": False,
                "error": str(error),
            }
        records.append(record)
        write_json(output / "summary.json", summary)
    summary["verification_complete"] = all(r["evidence_verified"] for r in records)
    summary["research_requirements_satisfied"] = all(r["requirement_satisfied"] for r in records)
    write_json(output / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(
        not args.output.resolve().is_relative_to(args.evidence.resolve()),
        "Verification output must be outside source evidence",
    )
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        data = args.plan.read_bytes()
        require(hashlib.sha256(data).hexdigest() == args.plan_sha256, "Replay plan digest differs")
        (args.output / "plan.json").write_bytes(data)
        summary = aggregate(json.loads(data), args.evidence.resolve(), args.output)
        return 0 if summary["research_requirements_satisfied"] else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        write_json(
            args.output / "verification-failure.json", {"error": str(error), "ci_admission": False}
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
