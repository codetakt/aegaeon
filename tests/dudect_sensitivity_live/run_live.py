# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Actual collector/ACK invocation and independently repeated evidence consumer.

This is a diagnostic qualification envelope, never an ordinary CI pass. Every
success receipt is derived from complete files and authenticated replay.
"""

import argparse
import json
import os
from pathlib import Path
import signal
import time

from build import sha
from live_runtime import identity, installed, replay, validate_identity
from analysis_contract import SOURCE
from contract import CONTRACT_SHA256, ROLES, TARGETS
from dudect_candidate import canonical, digest
from dudect_contract import assess_case, ObservationError
from dudect_diagnostics import validate_diagnostics, file_identity
from dudect_support import require
from qualification import evaluate
import receipts
import compare_receipts
import run_candidate
import runtime_dependencies
from run_analysis import interrupted

PROVIDER = (
    "ct_eq_32",
    "ct_eq_64",
    "ct_eq_128",
    "sha256",
    "hmac_sha256",
    "ed25519_verify",
    "hmac_sha256_key",
)


def load(path):
    return json.loads(Path(path).read_bytes())


def artifact_check(directory):
    artifact = load(directory / "artifact.json")
    manifest = load(directory / "build-manifest.json")
    require(sha(directory / "native") == artifact["binary_sha256"], "Changed diagnostic ELF")
    require(
        sha(directory / "build-manifest.json") == artifact["build_manifest_sha256"]
        and digest(canonical(manifest)) == artifact["binding"]["build_sha256"],
        "Changed native build binding",
    )
    require(
        sha(directory / "provider.c") == manifest["generated_source_sha256"],
        "Changed native source",
    )
    for path, value in artifact["dynamic_libraries"].items():
        require(sha(path) == value, "Changed native dependency")
    require(
        manifest["schema"]
        in ("six-case-sensitivity-native/1", "legacy-compare-sensitivity-native/1"),
        "Unsupported diagnostic schema",
    )
    compare = manifest["schema"] == "legacy-compare-sensitivity-native/1"
    implementation = (
        {"build_compare.py", "compare_signal.inc", "runtime_dependencies.py"}
        if compare
        else {"build.py", "signal.inc", "runtime_dependencies.py"}
    )
    for name, value in manifest["implementation"].items():
        require(
            name in implementation and sha(Path(__file__).resolve().parent / name) == value,
            "Changed diagnostic implementation",
        )
    require(
        set(manifest["implementation"]) == implementation,
        "Incomplete diagnostic implementation binding",
    )
    if manifest["schema"] in (
        "six-case-sensitivity-native/1",
        "legacy-compare-sensitivity-native/1",
    ):
        require(
            sha(directory / "runtime-dependencies.json") == artifact["runtime_dependencies_sha256"],
            "Changed dependency discovery receipt",
        )
        runtime = load(directory / "runtime-dependencies.json")
        require(
            runtime["method"] == "elf-pt-interp-list/1"
            and runtime["binary_sha256"] == artifact["binary_sha256"]
            and runtime["dynamic_libraries"] == artifact["dynamic_libraries"]
            and runtime["interpreter"] == runtime_dependencies.interpreter(directory / "native"),
            "Wrong dependency discovery receipt",
        )
    return artifact, manifest


def verify(output):  # noqa: PLR0915 -- ordered evidence checks retain each rejection boundary
    invocation = load(output / "invocation.json")
    analysis = invocation["analysis"]
    validate_identity(analysis)
    artifact, manifest = artifact_check(Path(invocation["artifact"]))
    require(artifact == invocation["artifact_record"], "Artifact differs from invocation")
    bindings = {n: invocation["bindings"][n] for n in invocation["case_order"]}
    compare = manifest["schema"] == "legacy-compare-sensitivity-native/1"
    suite = "legacy" if compare else "nix"
    require(
        list(bindings) == ["compare"] if compare else set(bindings) <= set(PROVIDER),
        "Wrong diagnostic case order",
    )
    for name, b in bindings.items():
        require(
            b == {"case_id": suite + "/" + name, "profile": "pr", **artifact["binding"]},
            "Wrong case binding",
        )
    process = load(output / "process.json")
    require(
        process["exit"] == 0 and process["collection_complete"] is True, "Native did not complete"
    )
    validate_diagnostics(output, process, bindings, "pr")
    rows = load(output / "observations.json")
    require(
        [load_line(x) for x in (output / "native.stdout").read_bytes().splitlines()]
        == [r for n in bindings for r in rows[n]],
        "Native stdout/history mismatch",
    )
    effective = replay(output, bindings, rows, analysis)
    sidecar = (compare_receipts if compare else receipts).verify(
        output, bindings, analysis["profile"], artifact["kind"]
    )
    entries = [load_line(x) for x in (output / "analysis-prefixes.jsonl").read_bytes().splitlines()]
    expected_identity = {
        "contract_sha256": CONTRACT_SHA256,
        "analysis_sha256": digest(canonical(analysis)),
        "source_sha256": manifest["generated_source_sha256"],
    }
    assessments = []
    for name in bindings:
        selected = [x for x in entries if x["proof"]["effective"]["case"] == name]
        require(len(selected) == 8, "Incomplete live case evidence")
        proofs = [x["proof"] for x in selected]
        history = [x for x in effective if x["case"] == name]
        cid = bindings[name]["case_id"]
        crop_records = [p["crop_record"] for p in proofs] if cid in TARGETS else None
        provenance = []
        for row, proof, original in zip(history, proofs, rows[name], strict=True):
            p = {
                "case_id": cid,
                "look": row["look"],
                "through_batch": original["batches"],
                "identity": expected_identity,
                "row_sha256": digest(canonical(row)),
                "prefix_sha256": proof["original_sparse_proof"]["prefix_sha256"],
                "verified_native_tests": [row["tests"][0], row["tests"][101]]
                if cid in TARGETS
                else row["tests"],
                "native_counts": {str(i): s[:2] for i, s in enumerate(original["statistics"])},
            }
            if crop_records is not None:
                p["crop_record_sha256"] = digest(canonical(proof["crop_record"]))
            provenance.append(p)
        original_history = [p["original_sparse_proof"]["history"]["original"] for p in proofs]
        try:
            original_role = assess_case(cid, ROLES[cid], original_history, "pr")
        except ObservationError as error:
            original_role = {
                "case_id": cid,
                "role": ROLES[cid],
                "requirement_satisfied": False,
                "failure": str(error),
                "statistical_outcome": original_history[-1]["candidate_statistical_outcome"],
            }
        # No success flags supplied by callers: these follow the checks above.
        verified_receipts = dict.fromkeys(
            ("binding", "frames", "inputs", "signal", "resources", "process"), True
        )
        result = evaluate(
            cid,
            analysis["profile"],
            history,
            crop_records,
            provenance,
            expected_identity,
            original_role,
            verified_receipts,
            time.monotonic() + 10,
        )
        assessments.append(result)
    return {
        "schema": "role-live-qualified/3",
        "analysis": analysis,
        "assessment": assessments,
        "qualified": all(
            r["schema"] == "dudect-role-assessment/3"
            and r["effective_result"]["requirement_satisfied"]
            for r in assessments
        ),
        "input_receipt": sidecar,
        "native_kind": artifact["kind"],
        "evidence": {
            p.name: file_identity(p)
            for p in output.iterdir()
            if p.is_file() and p.name not in ("qualification.json", "failure.json")
        },
        "adopted": False,
        "ci_admission": False,
    }


def load_line(data):
    return json.loads(data)


def execute(artifact_dir, output, profile, target, cpus, packet, unit):  # noqa: PLR0913, PLR0917 -- explicit fields from the frozen invocation contract
    require(
        len(cpus) == 2 and len(set(cpus)) == 2 and set(cpus) <= os.sched_getaffinity(0),
        "Invalid launch CPUs",
    )
    os.sched_setaffinity(0, set(cpus))
    artifact, manifest = artifact_check(artifact_dir)
    compare = manifest["schema"] == "legacy-compare-sensitivity-native/1"
    suite = "legacy" if compare else "nix"
    target_inventory = compare_receipts.TARGETS if compare else receipts.TARGETS
    fixture = artifact["kind"] == "injected_clock"
    require(
        (target in target_inventory) if fixture else target is None,
        "Wrong fixture/physical target selection",
    )
    names = (target,) if fixture else ("compare",) if compare else PROVIDER
    output.mkdir(parents=True, exist_ok=False)
    analysis = identity(packet, unit, profile)
    bindings = {
        n: {"case_id": suite + "/" + n, "profile": "pr", **artifact["binding"]} for n in names
    }
    invocation = {
        "analysis": analysis,
        "artifact": str(artifact_dir),
        "artifact_record": artifact,
        "bindings": bindings,
        "case_order": list(names),
        "cpus": cpus,
    }
    (output / "invocation.json").write_bytes(canonical(invocation))
    os.environ.update(
        PYTHONDONTWRITEBYTECODE="1",
        AEGAEON_SENSITIVITY_PROFILE=profile,
        AEGAEON_SENSITIVITY_INPUTS=str(output / "signal.inputs"),
    )
    if fixture:
        os.environ["AEGAEON_SENSITIVITY_TARGET"] = target
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    try:
        with installed(analysis):
            run_candidate.collect(SOURCE, output, artifact_dir / "native", "pr", bindings)
        report = verify(output)
        (output / "qualification.json").write_bytes(canonical(report))
        return report  # noqa: TRY300 -- failure capture preserves partial evidence
    except BaseException as error:
        (output / "failure.json").write_bytes(
            canonical({"type": type(error).__name__, "error": str(error)})
        )
        raise


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--artifact", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--profile", choices=receipts.PROFILES)
    p.add_argument("--target", choices=(*receipts.TARGETS, *compare_receipts.TARGETS))
    p.add_argument("--cpus", type=int, nargs=2)
    p.add_argument("--packet")
    p.add_argument("--unit")
    p.add_argument("--verify-only", action="store_true")
    a = p.parse_args()
    r = (
        verify(a.output)
        if a.verify_only
        else execute(a.artifact, a.output, a.profile, a.target, a.cpus, a.packet, a.unit)
    )
    print(
        json.dumps(
            {
                "qualified": r["qualified"],
                "cases": len(r["assessment"]),
                "failures": [
                    x["failure_details"] for x in r["assessment"] if not x["qualification_passed"]
                ],
            }
        )
    )
    raise SystemExit(0 if r["qualified"] else 1)
