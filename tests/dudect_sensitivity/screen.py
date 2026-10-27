# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I002, TRY003
"""Finite diagnostic screen; never replace the original statistical role.

Signal cases require the same completion, raw floor and numerical validity as
the actual gate. Additional final eligibility and crop1 obligations apply.
"""

import json

LOOK_BATCHES = [1, 2, 3, 4, 5, 6, 7, 16]


def evaluate(history, scope, ordinary_assessment):  # noqa: C901, PLR0912 -- ordered evidence checks retain each rejection boundary
    if scope not in ("ordinary", "zero", "early", "late"):
        raise ValueError("Unreviewed scope")
    failures = []
    if len(history) != 8 or [r["look"] for r in history] != list(range(1, 9)):
        failures.append("incomplete_look_schedule")
    if not history:
        return {"passed": False, "failures": failures, "scope": scope, "adopted": False}
    last = history[-1]
    if not last["collection_complete"] or min(last["raw_class_counts"]) < 200000:
        failures.append("incomplete_schedule_or_raw_floor")
    if any(r["numerically_unresolved_ever"] for r in history):
        failures.append("numerically_unresolved")
    if any([t["id"] for t in r["tests"]] != list(range(102)) for r in history):
        failures.append("invalid_statistic_inventory")
    if not all(t["eligible"] for t in last["tests"]):
        failures.append("final_statistic_ineligible")
    if scope in ("ordinary", "zero"):
        if not ordinary_assessment["requirement_satisfied"]:
            failures.append("original_role_not_satisfied")
    else:
        expected_looks = range(1, 8) if scope == "early" else [8]
        if not any(1 in r["detected_now"] for r in history if r["look"] in expected_looks):
            failures.append("required_crop1_signal_not_detected")
        if 1 not in last["detected_ever"]:
            failures.append("crop1_detection_not_retained")
        if scope == "late" and any(r["detected_now"] for r in history if r["look"] < 8):
            failures.append("unexpected_detection_before_signal")
    return {
        "passed": not failures,
        "failures": failures,
        "scope": scope,
        "ordinary_assessment": ordinary_assessment,
        "adopted": False,
        "power_established": False,
    }


def check_receipts(stderr, scope, frames):
    """Independently derive signal population from all native labels, incl pilot."""
    records = [
        json.loads(s.split(" ", 1)[1])
        for s in stderr.splitlines()
        if s.startswith("HMAC_SIGNAL_FRAME ")
    ]
    if len(records) != 17 or len(frames) != 17:
        raise ValueError("Incomplete signal receipt schedule")
    scope_id = {"zero": 0, "early": 1, "late": 2}[scope]
    for batch, (r, classes) in enumerate(zip(records, frames, strict=True)):
        enabled = (scope == "early" and 1 <= batch <= 8) or (scope == "late" and 9 <= batch <= 16)
        expected = {
            "batch": batch,
            "samples": 65536,
            "signal_samples": sum(classes) if enabled else 0,
            "scope": scope_id,
        }
        if len(classes) != 65536 or any(c not in (0, 1) for c in classes) or r != expected:
            raise ValueError("Signal receipt/input disagreement")
    complete = [s for s in stderr.splitlines() if s.startswith("HMAC_SIGNAL_COMPLETE ")]
    if complete != ['HMAC_SIGNAL_COMPLETE {"frames":17,"prepared":1114112}']:
        raise ValueError("Incomplete final signal receipt")
