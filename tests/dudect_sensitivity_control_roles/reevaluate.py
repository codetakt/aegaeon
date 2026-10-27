# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I001, I002, TRY003
"""Separate retained-data role correction, after original-prefix replay.

Original bindings/results are immutable. This does not establish a new native
execution, active consumer equivalence, P1 pass, P2 permission, or CI admission.
"""

import argparse
import copy
import hashlib
import json
import time
from pathlib import Path
from contract import CONTRACT_SHA256, ROLES, TARGETS, identity
from qualification import evaluate, digest, RECEIPTS


def file_hash(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def evaluate_saved(root, controls_only=False):  # noqa: PLR0915 -- ordered evidence checks retain each rejection boundary
    rows = json.loads((root / "observations.json").read_bytes())
    proofs = [
        json.loads(l)["proof"]
        for l in (root / "analysis-prefixes.jsonl").read_bytes().splitlines()  # noqa: E741 -- historical look identifier retained in the measured evaluator
    ]
    effective = json.loads((root / "effective-decisions.json").read_bytes())
    assert effective == [p["effective"] for p in proofs]
    bindings = {n: r[0]["binding"] for n, r in rows.items()}
    inputs = {
        n: {"sha256": file_hash(root / n), "bytes": (root / n).stat().st_size}
        for n in (
            "native.timing",
            "observations.json",
            "analysis-prefixes.jsonl",
            "effective-decisions.json",
            "invocation.json",
        )
    }
    invocation = json.loads((root / "invocation.json").read_bytes())
    old_analysis = invocation["analysis"]
    profile = old_analysis.get("profile", "ordinary")
    if profile not in (
        "ordinary",
        "zero",
        "full",
        "early_half",
        "late_half",
        "early_short",
        "late_short",
        "history",
        "lower_tail",
    ):
        raise ValueError("Unknown retained profile")
    report = {
        "schema": "original-control-role-reevaluation/1",
        "original_analysis": old_analysis,
        "corrected_qualification": identity(),
        "native_bindings": bindings,
        "source_binding_kind": "digest of retained native binding set",
        "input_files": inputs,
        "native_clock": "retained; not newly executed",
        "original_prefix_replay_required_separately": True,
        "ci_admission": False,
    }
    derived = {
        "contract_sha256": CONTRACT_SHA256,
        "source_sha256": digest(bindings),
        "analysis_sha256": digest(report),
    }
    old_report = (
        json.loads((root / "qualification.json").read_bytes())
        if (root / "qualification.json").exists()
        else None
    )
    assessments = []
    for name, binding in bindings.items():
        cid = binding["case_id"]
        role = ROLES[cid]
        if controls_only and role != "measurement_positive_control":
            continue
        selected = [p for p in proofs if p["effective"]["case"] == name]
        assert len(selected) == 8
        history = [p["effective"] for p in selected]
        crops = [p["crop_record"] for p in selected] if cid in TARGETS else None
        provenance = []
        for current, p, original in zip(history, selected, rows[name], strict=True):
            native = p["original_sparse_proof"]
            assert native["row_sha256"] == digest(original) and native["case"] == name  # noqa: PT018 -- fixed functional fixture retains its combined obligation
            q = {
                "case_id": cid,
                "look": current["look"],
                "through_batch": original["batches"],
                "identity": copy.deepcopy(derived),
                "row_sha256": digest(current),
                "prefix_sha256": native["prefix_sha256"],
                "verified_native_tests": [current["tests"][0], current["tests"][101]]
                if crops is not None
                else current["tests"],
                "native_counts": {str(i): s[:2] for i, s in enumerate(original["statistics"])},
            }
            if crops is not None:
                q["crop_record_sha256"] = digest(p["crop_record"])
            provenance.append(q)
        old = (
            next((r for r in old_report["assessment"] if r["case_id"] == cid), None)
            if old_report
            else None
        )
        original = (
            old["original_role_result"]
            if old
            else {"case_id": cid, "status": "preserved in separately verified original report"}
        )
        got = evaluate(
            cid,
            profile,
            history,
            crops,
            provenance,
            derived,
            original,
            dict.fromkeys(RECEIPTS, True),
            time.monotonic() + 10,
        )
        # Receipt success is conditional on the separately completed raw replay, not
        # a new claim from this retained-data requirements comparison.
        if old and role != "measurement_positive_control":
            for key in (
                "qualification_passed",
                "all_final_statistics_eligible",
                "final_raw0_101_eligible",
                "raw_floor_met",
                "support_limitations",
                "numeric_unresolved_ever",
                "presignal_detections",
                "failures",
                "failure_details",
                "detection_requirement_satisfied",
            ):
                assert got[key] == old[key], (cid, key)
            assert [(w["look"], w["statistic"]) for w in got["witnesses"]] == [
                (w["look"], w["statistic"]) for w in old["witnesses"]
            ]
        assessments.append(
            {
                "original_live_qualification": old,
                "corrected_retained_qualification": got,
                "qualification_changed": old is not None
                and old["qualification_passed"] != got["qualification_passed"],
            }
        )
    report["assessment"] = assessments
    report["all_corrected_conditions_met_conditional_on_replay"] = all(
        x["corrected_retained_qualification"]["qualification_passed"] for x in assessments
    )
    report["counts"] = {
        "cases": len(assessments),
        "changed": sum(x["qualification_changed"] for x in assessments),
        "corrected_qualified": sum(
            x["corrected_retained_qualification"]["qualification_passed"] for x in assessments
        ),
    }
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("root", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--controls-only", action="store_true")
    a = p.parse_args()
    r = evaluate_saved(a.root, a.controls_only)
    a.output.write_text(json.dumps(r, indent=2) + "\n")
    print(json.dumps(r["counts"]))
