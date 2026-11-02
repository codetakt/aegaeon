"""Report ordinary evidence after replay, without changing the measured evaluator.

Run in a pinned interpreter with the matching measured modules on PYTHONPATH.
The expected invocation digest comes from the fixed plan, not from this report.
This is local verification, not producer authentication or CI admission.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import stat
import sys
import time
from pathlib import Path
from typing import Any

MAX_FILES = 512
MAX_BYTES = 4 * 1024**3
NONDETECTION_ROLES = {"measurement_negative_control", "protected_input_observation"}


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


REPORTER_SHA256 = file_digest(Path(__file__))


def snapshot(directory: Path) -> dict[str, Any]:
    """Hash a quiescent recovered process directory with bounded streaming reads."""
    require(not directory.is_symlink() and directory.is_dir(), "Invalid evidence directory")
    files: dict[str, Any] = {}
    total = 0
    for path in sorted(directory.iterdir()):
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), "Non-regular recovered evidence")
        total += before.st_size
        require(len(files) < MAX_FILES and total <= MAX_BYTES, "Offline evidence size limit")
        value = file_digest(path)
        after = path.lstat()
        require(
            all(
                getattr(before, field) == getattr(after, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            ),
            "Evidence changed while hashing",
        )
        files[path.name] = {"bytes": before.st_size, "sha256": value}
    require(bool(files), "Empty evidence directory")
    return files


def axes(assessment: dict[str, Any]) -> dict[str, Any]:
    """Make a budget-qualified nondetection distinct from the legacy outcome."""
    for field in (
        "qualification_passed",
        "raw_floor_met",
        "final_raw0_101_eligible",
        "all_final_statistics_eligible",
        "evidence_valid",
        "execution_valid",
    ):
        require(type(assessment[field]) is bool, f"Invalid assessment field: {field}")
    require(
        assessment["effective_result"]["requirement_satisfied"]
        is assessment["qualification_passed"],
        "Inconsistent qualification result",
    )
    old = assessment["statistical_outcome"]
    require(old in {"detected", "budget_nondetection", "not_evaluable"}, "Unknown outcome")
    nondetection = all(
        assessment[k]
        for k in (
            "raw_floor_met",
            "final_raw0_101_eligible",
            "all_final_statistics_eligible",
            "evidence_valid",
            "execution_valid",
        )
    )
    return {
        "legacy_statistical_outcome": old,
        "observation": "detected"
        if old == "detected"
        else (
            "budget_nondetection"
            if old == "budget_nondetection" and nondetection
            else "not_evaluable"
        ),
        "qualification_passed": assessment["qualification_passed"],
        "raw_floor_met": assessment["raw_floor_met"],
        "legacy_execution_valid": assessment["execution_valid"],
        "legacy_execution_valid_basis": "caller checks; not independent lifecycle evidence",
    }


def detection_changes(
    proofs: list[dict[str, Any]],
    case_id: str,
    role: str,
    significant: Any,
) -> dict[str, Any]:
    original: set[tuple[int, int]] = set()
    effective: set[tuple[int, int]] = set()
    require(len(proofs) == 8, "Incomplete reporting history")
    name = case_id.split("/", 1)[1]
    for look, proof in enumerate(proofs, 1):
        rows = (
            proof["original_sparse_proof"]["history"]["original"],
            proof["effective"],
        )
        for row, found in zip(rows, (original, effective), strict=True):
            require(row["look"] == look and row["case"] == name, "Wrong report prefix")
            require([t["id"] for t in row["tests"]] == list(range(102)), "Missing statistics")
            found.update((look, t["id"]) for t in row["tests"] if significant(t))
    original_only = sorted(original - effective)
    crops = [list(pair) for pair in original_only if 1 <= pair[1] <= 100]
    return {
        "comparison": "same statistic and look; not equivalent-power evidence",
        "original_detected_statistic_looks": len(original),
        "effective_detected_statistic_looks": len(effective),
        "original_only_statistic_looks": [list(pair) for pair in original_only],
        "original_only_crop_detections": crops,
        "nondetection_role": role in NONDETECTION_ROLES,
        "nondetection_role_original_only_crops": crops if role in NONDETECTION_ROLES else [],
        "original_gate_OR_applied": False,
    }


def verify_process(output: Path, invocation_sha256: str) -> dict[str, Any]:
    """Verify one planned ordinary executable, then emit an additional report.

    The imported package/analysis/ordinary modules are the pinned measured verifier.
    No native executable is run. Reject changes across replay; use recovered data
    that is not concurrently writable. This is not a hostile-filesystem sandbox.
    """
    # Deliberately load the caller's pinned verifier, never rewrite its identity.
    ordinary = importlib.import_module("ordinary")
    candidate = importlib.import_module("run_candidate")
    analysis_module = importlib.import_module("analysis_contract")
    diagnostics = importlib.import_module("dudect_diagnostics")
    package = importlib.import_module("dudect_package")
    live = importlib.import_module("live_runtime")

    before = snapshot(output)
    require(file_digest(Path(__file__)) == REPORTER_SHA256, "Reporter changed after import")
    require(before["invocation.json"]["sha256"] == invocation_sha256, "Wrong planned invocation")
    inv = json.loads((output / "invocation.json").read_bytes())
    require(inv["kind"] == "ordinary" and inv["profile"] == "ordinary", "Not ordinary evidence")
    analysis = inv["analysis"]
    live.validate_identity(analysis)
    require(analysis["profile"] == "ordinary", "Wrong analysis profile")
    index = package.checked_package(
        Path(inv["package"]), candidate.current_sources(analysis_module.SOURCE), inv["suite"]
    )
    executable = [entry for entry in index["executables"] if entry["name"] == inv["executable"]]
    require(
        len(executable) == 1 and executable[0]["cases"] == inv["case_order"],
        "Wrong executable inventory",
    )
    require(
        digest(canonical(index)) == inv["package_sha256"]
        and executable[0]["sha256"] == inv["binary_sha256"],
        "Planned artifact identity mismatch",
    )
    bindings = package.expected_bindings(index, "pr")["bindings"]
    bindings = {name: bindings[name] for name in inv["case_order"]}
    process = json.loads((output / "process.json").read_bytes())
    require(process["exit"] == 0 and process["collection_complete"] is True, "Incomplete process")
    diagnostics.validate_diagnostics(output, process, bindings, "pr")
    rows = json.loads((output / "observations.json").read_bytes())
    require(
        [json.loads(line) for line in (output / "native.stdout").read_bytes().splitlines()]
        == [row for name in bindings for row in rows[name]],
        "Native stdout mismatch",
    )
    live.replay(output, bindings, rows, analysis)
    entries = [
        json.loads(line)["proof"]
        for line in (output / "analysis-prefixes.jsonl").read_bytes().splitlines()
    ]
    assessments = ordinary.evaluate_proofs(
        bindings,
        rows,
        [{"proof": p} for p in entries],
        analysis,
        digest(canonical(index)),
    )
    saved = json.loads((output / "qualification.json").read_bytes())
    require(saved["assessment"] == assessments, "Changed saved assessment")
    require(
        saved["qualified"] is all(a["qualification_passed"] for a in assessments),
        "Changed saved result",
    )
    require(before == snapshot(output), "Evidence changed during replay")
    require(file_digest(Path(__file__)) == REPORTER_SHA256, "Reporter changed during replay")
    receipt = {
        "schema": "ordinary-local-replay-receipt/1",
        "invocation_sha256": invocation_sha256,
        "analysis_sha256": digest(canonical(analysis)),
        "native_package_sha256": digest(canonical(index)),
        "native_elf_sha256": executable[0]["sha256"],
        "files": before,
        "case_order": inv["case_order"],
        "verifier": {
            "reporter_sha256": REPORTER_SHA256,
            "ordinary_sha256": file_digest(Path(str(ordinary.__file__))),
            "python_sha256": file_digest(Path(sys.executable)),
        },
        "checks_completed": [
            "package",
            "analysis_identity",
            "process",
            "diagnostics",
            "stdout",
            "raw_prefix_replay",
            "saved_assessments",
            "unchanged_inputs",
        ],
        "producer_authentication_performed": False,
        "independent_operator_established": False,
        "external_lifecycle_verified": False,
    }
    receipt_sha = digest(canonical(receipt))
    reports = []
    for assessment in assessments:
        cid = assessment["case_id"]
        selected = [p for p in entries if p["effective"]["case"] == cid.split("/", 1)[1]]
        reports.append(
            {
                "case_id": cid,
                "role": assessment["role"],
                "expected_identity": {
                    "replay_receipt_sha256": receipt_sha,
                    "analysis_sha256": receipt["analysis_sha256"],
                    "assessment_sha256": digest(canonical(assessment)),
                    "contract_sha256": assessment["contract_sha256"],
                },
                "axes": axes(assessment),
                "detection_changes": detection_changes(
                    selected, cid, assessment["role"], analysis_module.significant
                ),
            }
        )
    return {
        "schema": "ordinary-replay-report/1",
        "replay_receipt": receipt,
        "replay_receipt_sha256": receipt_sha,
        "cases": reports,
        "qualification_passed": saved["qualified"],
        "ci_admission": False,
        "original_assessments_modified": False,
        "new_physical_trials": 0,
    }


def scheduled_ordinary(cutoff: float, *args: Any, **kwargs: Any) -> Any:
    """Install the absolute stream cutoff before ordinary installs live workers.

    An external owner must still provide independent stop, recovery and cleanup.
    This helper does not authorize or provision a measurement.
    """
    ordinary = importlib.import_module("ordinary")
    schedule = importlib.import_module("schedule")

    require(
        math.isfinite(cutoff) and time.monotonic() + 900 <= cutoff, "Invalid acquisition cutoff"
    )
    with schedule.installed(cutoff):
        return ordinary.execute(*args, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="quiescent recovered process directory"
    )
    parser.add_argument(
        "--invocation-sha256", required=True, help="exact digest from the fixed plan"
    )
    args = parser.parse_args()
    try:
        report = verify_process(args.output, args.invocation_sha256)
    except (OSError, ValueError, KeyError, TypeError, ImportError) as error:
        print(
            json.dumps({"verification_complete": False, "error": str(error), "ci_admission": False})
        )
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["qualification_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
