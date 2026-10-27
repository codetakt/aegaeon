# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I002, TRY003
"""Design-1 qualification, separate from the original statistical case role.

Inputs are authenticated/recomputed analysis histories, not producer pass flags.
The caller must supply explicit acquisition, binding and resource receipts.
"""

import copy
import hashlib
import json
from pathlib import Path

from analysis_contract import significant

HERE = Path(__file__).resolve().parent
CONTRACT = json.loads((HERE / "obligations.json").read_text())
CONTRACT_SHA256 = hashlib.sha256((HERE / "obligations.json").read_bytes()).hexdigest()
TARGETS = frozenset(CONTRACT["target_cases"])
OBLIGATIONS = {o["profile"]: o for o in CONTRACT["signal_obligations"]}
PROFILES = ("ordinary", "zero", *OBLIGATIONS)
RECEIPTS = ("binding", "frames", "inputs", "signal", "resources", "process")


def evaluate(case_id, profile, history, original_role, receipts):  # noqa: C901, PLR0912, PLR0915 -- ordered evidence checks retain each rejection boundary
    """Accumulate all failures; detection never waives common validity.

    Original role is required only for unsignalled cases. Its result is always
    retained. Counts of ineligible tests come from authenticated moment records;
    an absent count is invalid evidence, never an inferred floor success.
    """
    if profile not in PROFILES:
        raise ValueError("Unbound sensitivity profile")
    obligation = OBLIGATIONS.get(profile) if case_id in TARGETS else None
    required = obligation["statistics"] if obligation else []
    failures, details = set(), []

    def fail(reason, detail):
        failures.add(reason)
        details.append({"reason": reason, "detail": detail})

    if set(receipts) != set(RECEIPTS) or any(receipts.get(k) is not True for k in RECEIPTS):
        fail("evidence_invalid", "missing/failed common receipt")
    if len(history) != 8 or [r.get("look") for r in history] != list(range(1, 9)):
        fail("evidence_invalid", "incomplete look schedule")
    seen, unresolved, presignal = set(), [], []
    first_detection = None
    first_eligible = {i: None for i in required}  # noqa: C420 -- retain the measured dictionary construction
    final_eligible, raw_floor = False, False
    for row in history:
        look = row.get("look")
        if (
            row.get("case") != case_id.split("/")[-1]
            or row.get("profile") != "pr"
            or type(look) is not int
            or not 1 <= look <= 8
        ):
            fail("evidence_invalid", "case/profile/look mismatch")
        tests = row.get("tests", [])
        if [t.get("id") for t in tests] != list(range(102)):
            fail("evidence_invalid", f"statistic inventory at look {look}")
            continue
        actual = set()
        for test in tests:
            idx = test["id"]
            n = (test.get("n0"), test.get("n1"))
            valid_counts = all(type(x) is int and x >= 0 for x in n)
            if not valid_counts:
                fail("evidence_invalid", f"missing count at {look}/{idx}")
            if test.get("eligible") is True:
                if (
                    not valid_counts
                    or min(n) < CONTRACT["numeric_contract"]["minimum_statistic_class_count"]
                ):
                    fail("count_inconclusive", f"eligible flag bypasses floor at {look}/{idx}")
                if idx in first_eligible and first_eligible[idx] is None:
                    first_eligible[idx] = look
            if test.get("reason") == "numerically_unresolved":
                unresolved.append({"look": look, "statistic": idx})
            try:
                detected = significant(test)
            except (KeyError, TypeError, ValueError):
                fail("evidence_invalid", f"invalid numerical decision at {look}/{idx}")
                detected = False
            if detected:
                if test.get("eligible") is not True or not valid_counts or min(n) < 10001:
                    fail("evidence_invalid", f"ineligible detection at {look}/{idx}")
                else:
                    actual.add(idx)
        seen.update(actual)
        if (
            row.get("detected_now") != sorted(actual)
            or row.get("detected_ever") != sorted(seen)
            or row.get("numerically_unresolved_ever") != unresolved
        ):
            fail("evidence_invalid", f"nonabsorbing/inconsistent history at look {look}")
        if obligation:
            if look in obligation["forbidden_presignal_looks"]:
                presignal.extend(
                    {"look": look, "statistic": i}
                    for i in sorted(actual.intersection(obligation["presignal_statistic_scope"]))
                )
            if (
                first_detection is None
                and look in obligation["eligible_detection_looks"]
                and actual.intersection(required)
            ):
                first_detection = look
        if look == 8:
            counts = row.get("raw_class_counts", [])
            raw_floor = len(counts) == 2 and all(type(n) is int and n >= 200000 for n in counts)
            final_eligible = all(
                t.get("eligible") is True
                and all(type(t.get(k)) is int and t[k] >= 10001 for k in ("n0", "n1"))
                for t in tests
            )
            if row.get("collection_complete") is not True:
                fail("evidence_invalid", "incomplete acquisition")
    if not final_eligible or not raw_floor:
        fail("count_inconclusive", "final eligibility/raw floor not established")
    if unresolved:
        fail("numerically_unresolved", "unresolved numerical history")
    if presignal:
        fail("unexpected_presignal_detection", "detection before assigned signal")
    if obligation:
        if first_detection is None or not seen.intersection(required):
            fail("required_detection_missing", "required eligible statistic absent by deadline")
    elif original_role.get("requirement_satisfied") is not True:
        fail("original_role_failed", "original unsignalled role not satisfied")
    return {
        "schema": "dudect-sensitivity-qualification/1",
        "contract_sha256": CONTRACT_SHA256,
        "case_id": case_id,
        "profile": profile,
        "obligation_id": obligation["id"] if obligation else None,
        "original_role_result": copy.deepcopy(original_role),
        "satisfied": not failures,
        "required_statistics": required,
        "first_eligible_look": first_eligible,
        "first_eligible_detection_look": first_detection,
        "detected_ever": sorted(seen),
        "presignal_detections": presignal,
        "all_final_statistics_eligible": final_eligible,
        "raw_floor_met": raw_floor,
        "numeric_unresolved_ever": unresolved,
        "failures": sorted(failures),
        "failure_details": details,
        "adopted": False,
        "physical_power_established": False,
    }


def counted_history(history, proofs):
    """Attach missing ineligible crop counts from corresponding exact moments."""
    result = copy.deepcopy(history)
    if len(result) != len(proofs):
        raise ValueError("Missing prefix proofs")
    for row, proof in zip(result, proofs, strict=True):
        if proof["effective"] != history[row["look"] - 1]:
            raise ValueError("History does not match authenticated proof")
        dist = proof["distributed"]
        if dist:
            if dist["look"] != row["look"]:
                raise ValueError("Moment look mismatch")
            for test, pair in zip(row["tests"][1:101], dist["moments"], strict=True):
                for group, key in enumerate(("n0", "n1")):
                    count = pair[group]["n"]
                    if key in test and test[key] != count:
                        raise ValueError("Count mismatch")
                    test[key] = count
    return result
