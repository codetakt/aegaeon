# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Ordinary full-suite path with the fixed seven-case calibration and role gate.

Native measurement packages are unchanged. Their existing input capture/audit
coverage is reported explicitly; this does not invent missing CT32/64/128 bytes.
"""

import argparse
import json
import signal
from pathlib import Path
import time

from analysis_contract import SOURCE
from contract import CONTRACT_SHA256, ROLES, TARGETS
from dudect_candidate import canonical, digest
from dudect_contract import assess_case, ObservationError
from dudect_diagnostics import validate_diagnostics, file_identity  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
from dudect_package import checked_package, expected_bindings
from dudect_support import require
from live_runtime import identity, installed, replay, validate_identity
from qualification import evaluate
import run_candidate
from run_analysis import interrupted


def load(path):
    return json.loads(Path(path).read_bytes())


def evaluate_proofs(bindings, rows, entries, analysis, source_sha256):
    expected = {
        "contract_sha256": CONTRACT_SHA256,
        "analysis_sha256": digest(canonical(analysis)),
        "source_sha256": source_sha256,
    }
    results = []
    for name, binding in bindings.items():
        cid = binding["case_id"]
        proofs = [e["proof"] for e in entries if e["proof"]["effective"]["case"] == name]
        require(len(proofs) == 8, "Incomplete ordinary history")
        history = [p["effective"] for p in proofs]
        crops = [p["crop_record"] for p in proofs] if cid in TARGETS else None
        provenance = []
        for current, p, original in zip(history, proofs, rows[name], strict=True):
            q = {
                "case_id": cid,
                "look": current["look"],
                "through_batch": original["batches"],
                "identity": expected,
                "row_sha256": digest(canonical(current)),
                "prefix_sha256": p["original_sparse_proof"]["prefix_sha256"],
                "verified_native_tests": [current["tests"][0], current["tests"][101]]
                if crops is not None
                else current["tests"],
                "native_counts": {str(i): s[:2] for i, s in enumerate(original["statistics"])},
            }
            if crops is not None:
                q["crop_record_sha256"] = digest(canonical(p["crop_record"]))
            provenance.append(q)
        try:
            original_role = assess_case(
                cid,
                ROLES[cid],
                [p["original_sparse_proof"]["history"]["original"] for p in proofs],
                "pr",
            )
        except ObservationError as error:
            original_role = {
                "case_id": cid,
                "role": ROLES[cid],
                "requirement_satisfied": False,
                "failure": str(error),
            }
        results.append(
            evaluate(
                cid,
                "ordinary",
                history,
                crops,
                provenance,
                expected,
                original_role,
                dict.fromkeys(
                    ("binding", "frames", "inputs", "signal", "resources", "process"), True
                ),
                time.monotonic() + 10,
            )
        )
    return results


def verify(output, expected_invocation_sha256):
    require(
        digest((output / "invocation.json").read_bytes()) == expected_invocation_sha256,
        "Wrong planned ordinary invocation",
    )
    inv = load(output / "invocation.json")
    a = inv["analysis"]
    validate_identity(a)
    require(a["profile"] == "ordinary", "Ordinary role cannot be changed to signal role")
    package = Path(inv["package"])
    index = checked_package(package, run_candidate.current_sources(SOURCE), inv["suite"])
    require(index == inv["package_index"], "Native package changed")
    expected = expected_bindings(index, "pr")["bindings"]
    assessments = []
    coverage = []
    for entry in index["executables"]:
        dest = output / "executions" / entry["name"]
        bindings = {n: expected[n] for n in entry["cases"]}
        process = load(dest / "process.json")
        require(
            process["exit"] == 0 and process["collection_complete"] is True,
            "Ordinary process incomplete",
        )
        validate_diagnostics(dest, process, bindings, "pr")
        rows = load(dest / "observations.json")
        require(
            [json.loads(l) for l in (dest / "native.stdout").read_bytes().splitlines()]  # noqa: E741 -- historical look identifier retained in the measured evaluator
            == [r for n in bindings for r in rows[n]],
            "Ordinary stdout mismatch",
        )
        replay(
            dest, bindings, rows, a
        )  # validates every prefix, unchanged tests and resource receipts
        proofs = [
            json.loads(l)
            for l in (dest / "analysis-prefixes.jsonl").read_bytes().splitlines()  # noqa: E741 -- historical look identifier retained in the measured evaluator
        ]
        assessments.extend(evaluate_proofs(bindings, rows, proofs, a, digest(canonical(index))))
        coverage.append(
            {
                "executable": entry["name"],
                "native_input_cases": process["diagnostics"]["timing"]["input_cases"],
                "ordinary_source_input_audit": "unchanged",
                "added_signal": False,
            }
        )
    return {
        "schema": "ordinary-role-qualification/3",
        "analysis": a,
        "assessment": assessments,
        "qualified": all(
            r["schema"] == "dudect-role-assessment/3"
            and r["effective_result"]["requirement_satisfied"]
            for r in assessments
        ),
        "input_coverage": coverage,
        "adopted": False,
        "ci_admission": False,
    }


def execute(package, output, suite, packet, unit):
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    output.mkdir(parents=True, exist_ok=False)
    index = checked_package(package, run_candidate.current_sources(SOURCE), suite)
    a = identity(packet, unit, "ordinary")
    expected = expected_bindings(index, "pr")["bindings"]
    inv = {"package": str(package), "package_index": index, "analysis": a, "suite": suite}
    (output / "invocation.json").write_bytes(canonical(inv))
    inv_sha = digest(canonical(inv))
    try:
        with installed(a):
            for entry in index["executables"]:
                dest = output / "executions" / entry["name"]
                dest.mkdir(parents=True)
                bindings = {n: expected[n] for n in entry["cases"]}
                run_candidate.collect(
                    SOURCE, dest, package / entry["relative_binary"], "pr", bindings
                )
        report = verify(output, inv_sha)
        (output / "qualification.json").write_bytes(canonical(report))
        return report  # noqa: TRY300 -- failure capture preserves partial evidence
    except BaseException as error:
        (output / "failure.json").write_bytes(
            canonical({"type": type(error).__name__, "error": str(error)})
        )
        raise


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--package", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--suite", choices=("legacy", "nix"))
    p.add_argument("--packet")
    p.add_argument("--unit")
    p.add_argument("--verify-only", action="store_true")
    p.add_argument("--invocation-sha256")
    a = p.parse_args()
    result = (
        verify(a.output, a.invocation_sha256)
        if a.verify_only
        else execute(a.package, a.output, a.suite, a.packet, a.unit)
    )
    print(json.dumps({"qualified": result["qualified"], "cases": len(result["assessment"])}))
    raise SystemExit(0 if result["qualified"] else 1)
