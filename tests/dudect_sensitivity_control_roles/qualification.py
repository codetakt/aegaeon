# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Design-2 positive qualification and exact support validation.

Full assessment consumes already authenticated native-prefix proofs and receipt
results. Kernel assessment explicitly lacks those prerequisites. Neither API is
an adopted gate. Tail certificates are recomputed, not accepted as pass flags.
"""

import copy
import hashlib
import json
import math
import time
from functools import lru_cache
from fractions import Fraction

from analysis_contract import significant
from dudect_contract import CHARACTERIZATION_ROLES, NONDETECTION_ROLES, POSITIVE_STATISTICS
from enclosed_tail import ALPHA, enclose
from contract import (
    BASE,  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
    CONTRACT_SHA256,
    FLOOR,
    LOOKS,
    OBLIGATIONS,
    PROFILES,
    RAW_FLOOR,
    ROLES,
    TARGETS,
)

RECEIPTS = ("binding", "frames", "inputs", "signal", "resources", "process")


@lru_cache(maxsize=1024)
def certified(t, degrees):
    return enclose(t, degrees)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def count_pair(value):
    require(
        isinstance(value, list)
        and len(value) == 2
        and all(type(n) is int and 0 <= n <= 1048400 for n in value),
        "Invalid class counts",
    )
    return value


def tail_decision(test, deadline=None):
    """Verify exact bounds at the frozen binary64 inputs, including the alpha."""
    require(
        type(test.get("t")) is float
        and math.isfinite(test["t"])
        and type(test.get("degrees")) is float
        and math.isfinite(test["degrees"])
        and test["degrees"] > 0,
        "Invalid Student inputs",
    )
    cert = test.get("interval")
    require(
        isinstance(cert, dict)
        and cert.get("t_hex") == test["t"].hex()
        and cert.get("degrees_hex") == test["degrees"].hex()
        and cert.get("target") == "mathematical_student_tail_at_frozen_binary64_t_df",
        "Missing or mismatched certified tail",
    )
    require(test.get("alpha") == float(ALPHA), "Changed numerical threshold")
    if cert.get("decision") == "numerically_unresolved":
        return "numerically_unresolved"
    attempts = cert.get("attempts", [])
    finite = [a for a in attempts if a.get("finite") is True]
    require(bool(finite), "No finite tail bound")

    def rational(x):
        require(
            isinstance(x, list)
            and len(x) == 2
            and all(type(n) is int and n.bit_length() <= 2048 for n in x)
            and x[1] > 0,
            "Invalid bound rational",
        )
        return Fraction(*x)

    lower, upper = (rational(finite[-1][k]) for k in ("lower", "upper"))
    require(0 <= lower <= upper <= 1, "Invalid tail bounds")
    decision = (
        "detected"
        if upper < ALPHA
        else "nondetected"
        if lower >= ALPHA
        else "numerically_unresolved"
    )
    require(cert.get("decision") == decision, "Forged tail decision")
    require(deadline is None or time.monotonic() < deadline, "Numerical verification deadline")
    require(
        certified(test["t"], test["degrees"]) == cert,
        "Certificate differs from recomputed Student enclosure",
    )
    require(deadline is None or time.monotonic() < deadline, "Numerical verification deadline")
    return decision


def inspect_crop(test, pair, upper_counts, deadline=None):
    require(type(test.get("eligible")) is bool, "Invalid eligibility flag")
    require(len(pair) == 2, "Missing complete class moments")
    counts, spreads = [], []
    for g, m in enumerate(pair):
        require(
            set(m) == {"n", "sum", "sum2"}
            and all(type(v) is int and v >= 0 and v.bit_length() <= 192 for v in m.values()),
            "Invalid integer moment",
        )
        n = m["n"]
        require(
            n <= upper_counts[g] and (n != 0 or m["sum"] == m["sum2"] == 0), "Invalid support count"
        )
        spread = n * m["sum2"] - m["sum"] ** 2
        require(spread >= 0, "Negative exact variance")
        counts.append(n)
        spreads.append(spread)
    reason = (
        "insufficient_count"
        if min(counts) < FLOOR
        else "degenerate_variance"
        if min(spreads) == 0
        else None
    )
    if reason:
        require(
            test["eligible"] is False and test.get("reason") == reason,
            "Ineligibility contradicts exact support",
        )
        require(
            not any(k in test for k in ("p", "legacy_p", "interval", "exact_p_numerator")),
            "Ineligible support cannot carry a p value",
        )
        for g, k in enumerate(("n0", "n1")):
            require(k not in test or test[k] == counts[g], "Wrong ineligible counts")
        return {"eligible": False, "counts": counts, "reason": reason, "detected": False}
    # Reproduce only the contracted rounding of exact sums before using Welch.
    require(
        test.get("method") == "student_interval_at_frozen_binary64"
        and not any(k.startswith("exact_p") for k in test),
        "Sparse inference cannot be transferred to new crops",
    )
    means = [m["sum"] / m["n"] for m in pair]
    variance = [(spreads[g] / counts[g]) / (counts[g] - 1) for g in (0, 1)]
    a, b = [variance[g] / counts[g] for g in (0, 1)]
    t = (means[0] - means[1]) / math.sqrt(a + b)
    df = (a + b) ** 2 / (a * a / (counts[0] - 1) + b * b / (counts[1] - 1))
    require(
        [test.get("n0"), test.get("n1")] == counts
        and [test.get("variance0"), test.get("variance1")] == variance
        and test.get("t") == t
        and test.get("degrees") == df,
        "Welch inputs disagree with exact moments",
    )
    decision = tail_decision(test, deadline)
    if decision == "numerically_unresolved":
        require(
            test["eligible"] is False and test.get("reason") == decision,
            "Unresolved numerical result marked eligible",
        )
        return {"eligible": False, "counts": counts, "reason": decision, "detected": False}
    require(test["eligible"] is True and "reason" not in test, "False degenerate/numerical status")
    return {"eligible": True, "counts": counts, "reason": None, "detected": decision == "detected"}


def inspect_crops(case_id, profile, records, deadline=None):
    """Validate all100 crops; no successful subset is selected after results."""
    require(case_id in ROLES and profile in PROFILES, "Unknown case/profile")
    require(case_id in TARGETS, "This crop proof is only defined for the seven calibrated cases")
    require(len(records) == 8, "Incomplete crop history")
    obligation = OBLIGATIONS.get(profile)
    seen, witnesses, limitations, unresolved, presignal, eligible_history = (
        set(),
        [],
        [],
        [],
        [],
        [],
    )
    for look, row in enumerate(records, 1):
        require(
            row["look"] == look and row["through_batch"] == LOOKS[look - 1], "Future/reordered look"
        )
        require([t["id"] for t in row["tests"]] == list(range(1, 101)), "Wrong crop inventory")
        require(len(row["moments"]) == len(row["cutoffs"]) == 100, "Incomplete crop proof")
        raw, reserved, testing = [
            count_pair(row[k]) for k in ("raw_class_counts", "reserved_counts", "test_counts")
        ]
        require(raw == [reserved[g] + testing[g] for g in (0, 1)], "Partition/raw counts differ")
        require(
            all(type(k) is int and 0 <= k < 2**63 for k in row["cutoffs"])
            and row["cutoffs"] == sorted(row["cutoffs"]),
            "Malformed cutoff order",
        )
        now, eligible = [], []
        for test, pair, cutoff in zip(row["tests"], row["moments"], row["cutoffs"], strict=True):
            check = inspect_crop(test, pair, testing, deadline)
            eligible.append(check["eligible"])
            if not check["eligible"]:
                limitations.append(
                    {
                        "look": look,
                        "statistic": test["id"],
                        "cutoff": cutoff,
                        "class_counts": check["counts"],
                        "reason": check["reason"],
                    }
                )
                if check["reason"] == "numerically_unresolved":
                    unresolved.append({"look": look, "statistic": test["id"]})
            if check["detected"]:
                now.append(test["id"])
                if obligation and look in obligation["forbidden_presignal_looks"]:
                    presignal.append({"look": look, "statistic": test["id"]})
                if (
                    obligation
                    and test["id"] in obligation["statistics"]
                    and look in obligation["eligible_detection_looks"]
                ):
                    witnesses.append(
                        {
                            "case_id": case_id,
                            "profile": profile,
                            "look": look,
                            "statistic": test["id"],
                            "cutoff": cutoff,
                            "class_counts": check["counts"],
                            "moments": copy.deepcopy(pair),
                            "tail_interval": copy.deepcopy(test["interval"]),
                            "record_sha256": digest(row),
                        }
                    )
        seen.update(now)
        require(
            now == row["detected_now"] and sorted(seen) == row["detected_ever"],
            "Dropped/forged crop detection history",
        )
        eligible_history.append(eligible)
    return {
        "detection_requirement_satisfied": bool(witnesses) if obligation else None,
        "witnesses": witnesses,
        "first_witness": witnesses[0] if witnesses else None,
        "detected_ever": sorted(seen),
        "support_limitations": limitations,
        "all_final_crops_eligible": all(eligible_history[-1]),
        "numeric_unresolved_ever": unresolved,
        "presignal_detections": presignal,
        "raw_floor_met": min(records[-1]["raw_class_counts"]) >= RAW_FLOOR,
    }


def assess_kernel(data, deadline=None):
    """Partial crop expectation only. Missing full102 context remains unknown."""
    case, profile = data["case_id"], data["profile"]
    special = (
        "pilot_main_common_drift",
        "max_distinct_support",
        "identical_values",
        "absent_class",
    )
    require(profile in (*OBLIGATIONS, *special), "Unknown kernel profile")
    check = inspect_crops(
        case, profile if profile in OBLIGATIONS else "zero", data["looks"], deadline
    )
    common = check["raw_floor_met"] and not check["numeric_unresolved_ever"]
    if profile in OBLIGATIONS:
        expectation = (
            common
            and check["detection_requirement_satisfied"]
            and not check["presignal_detections"]
        )
    elif profile == "pilot_main_common_drift":
        expectation = common and check["all_final_crops_eligible"] and not check["detected_ever"]
    elif profile == "max_distinct_support":
        expectation = common and check["all_final_crops_eligible"]
    else:
        expectation = not check["all_final_crops_eligible"] and not check["detected_ever"]
    return {
        "contract_sha256": CONTRACT_SHA256,
        "case_id": case,
        "profile": profile,
        **check,
        "crop_expectation_met": expectation,
        "qualification_passed": None,
        "all_final_statistics_eligible": None,
        "final_raw0_101_eligible": None,
        "evidence_status": "kernel_only",
        "missing_prerequisites": ["raw0/101", "authenticated native receipts"],
        "adopted": False,
    }


def evaluate(  # noqa: C901, PLR0912, PLR0913, PLR0915, PLR0917 -- ordered evidence checks retain each rejection boundary; explicit fields from the frozen invocation contract
    case_id,
    profile,
    history,
    crop_records,
    provenance,
    expected_identity,
    original_role,
    receipts,
    deadline=None,
):
    """Full diagnostic API; receipt and native test proofs come from the verifier.

    The function does not manufacture receipt success or accept a kernel as full
    evidence. Source/analysis and each full-row/prefix binding must be explicit.
    """
    require(case_id in ROLES and profile in PROFILES, "Unknown case/profile")
    positive = case_id in TARGETS and profile in OBLIGATIONS
    role = ROLES[case_id]
    original_positive = role == "measurement_positive_control"
    characterization = role in CHARACTERIZATION_ROLES
    require(
        role in NONDETECTION_ROLES or original_positive or characterization, "Unknown bound role"
    )
    failures, details = set(), []

    def fail(reason, detail):
        failures.add(reason)
        details.append({"reason": reason, "detail": detail})

    crop = None
    seen, numeric, pre, native_limitations = set(), [], [], []
    final_eligible = raw_stats = raw_floor = False
    try:
        require(deadline is None or time.monotonic() < deadline, "Qualification deadline")
        require(
            set(receipts) == set(RECEIPTS) and all(receipts[k] is True for k in RECEIPTS),
            "Missing/failed acquisition receipt",
        )
        require(
            expected_identity.get("contract_sha256") == CONTRACT_SHA256
            and all(
                isinstance(expected_identity.get(k), str) and len(expected_identity[k]) == 64
                for k in ("source_sha256", "analysis_sha256")
            ),
            "Missing analysis/source identity",
        )
        require(len(history) == len(provenance) == 8, "Incomplete full history")
        if case_id in TARGETS:
            crop = inspect_crops(case_id, profile, crop_records, deadline)
        else:
            require(crop_records is None, "Crop replacement outside fixed scope")
        for look, (row, proof) in enumerate(zip(history, provenance, strict=True), 1):
            require(
                row["case"] == case_id.split("/")[1]
                and row["profile"] == "pr"
                and row["look"] == look,
                "Case/profile/look mismatch",
            )
            require(
                proof["case_id"] == case_id
                and proof["look"] == look
                and proof["through_batch"] == LOOKS[look - 1]
                and proof["identity"] == expected_identity
                and proof["row_sha256"] == digest(row)
                and isinstance(proof["prefix_sha256"], str)
                and len(proof["prefix_sha256"]) == 64,
                "Missing/mixed current prefix identity",
            )
            tests = row["tests"]
            require([t["id"] for t in tests] == list(range(102)), "Wrong full statistic inventory")
            if crop is not None:
                cr = crop_records[look - 1]
                require(
                    tests[1:101] == cr["tests"]
                    and row["raw_class_counts"] == cr["raw_class_counts"],
                    "Full/crop row mismatch",
                )
                require(proof["crop_record_sha256"] == digest(cr), "Unbound crop evidence")
            unchanged = [tests[0], tests[101]] if crop is not None else tests
            require(
                proof["verified_native_tests"] == unchanged, "Changed original-population tests"
            )
            now, eligible = [], []
            for t in tests:
                idx = t["id"]
                require(type(t.get("eligible")) is bool, "Invalid native eligibility flag")
                if crop is not None and 1 <= idx <= 100:
                    pair = crop_records[look - 1]["moments"][idx - 1]
                    counts = [m["n"] for m in pair]
                else:
                    counts = count_pair(proof["native_counts"][str(idx)])
                if t["eligible"]:
                    require(min(counts) >= FLOOR, "Eligible test below floor")
                    if "t" in t and (crop is None or idx in (0, 101)):
                        require(
                            tail_decision(t, deadline) != "numerically_unresolved",
                            "Unresolved marked eligible",
                        )
                else:
                    reason = t.get("reason")
                    require(
                        reason
                        in ("insufficient_count", "degenerate_variance", "numerically_unresolved"),
                        "Unknown native ineligibility",
                    )
                    if reason == "insufficient_count":
                        require(min(counts) < FLOOR, "False native count shortage")
                    elif reason == "degenerate_variance":
                        require(min(counts) >= FLOOR, "Degenerate reason hides count shortage")
                    require(
                        not any(k in t for k in ("p", "exact_p_numerator"))
                        or reason == "numerically_unresolved",
                        "Ineligible native p value",
                    )
                if t.get("reason") == "numerically_unresolved":
                    numeric.append({"look": look, "statistic": idx})
                if not t["eligible"] and (crop is None or idx in (0, 101)):
                    native_limitations.append(
                        {
                            "look": look,
                            "statistic": idx,
                            "reason": t["reason"],
                            "class_counts": counts,
                        }
                    )
                eligible.append(t["eligible"] is True)
                if significant(t):
                    now.append(idx)
            seen.update(now)
            require(
                row["detected_now"] == now
                and row["detected_ever"] == sorted(seen)
                and row["numerically_unresolved_ever"] == numeric,
                "Invalid full detection/numeric history",
            )
            if positive and look in OBLIGATIONS[profile]["forbidden_presignal_looks"]:
                pre.extend({"look": look, "statistic": idx} for idx in now)
            if look == 8:
                require(row["collection_complete"] is True, "Incomplete final collection")
                raw_floor = min(count_pair(row["raw_class_counts"])) >= RAW_FLOOR
                final_eligible = all(eligible)
                raw_stats = eligible[0] and eligible[101]
        # Original positive controls test their designated statistic at an
        # eligible fixed look. Lower crops may exclude a separated class.
        # They are not product nondetection cases or C1/F sensitivity profiles.
        final_requirement = (
            raw_stats
            if positive
            else (True if original_positive or characterization else final_eligible)
        )
        if not raw_floor or not final_requirement:
            fail("count_inconclusive", "Required final eligibility/raw floor missing")
        if numeric:
            fail("numerically_unresolved", "Numerical issue anywhere in history")
        if pre:
            fail("unexpected_presignal_detection", "Signal not started")
        if positive:
            if not crop["detection_requirement_satisfied"]:
                fail("required_detection_missing", "No eligible required-set witness")
        else:
            role = ROLES[case_id]
            if role in NONDETECTION_ROLES:
                satisfied = not seen
            elif role == "measurement_positive_control":
                satisfied = POSITIVE_STATISTICS[case_id.split("/")[1]] in seen
            else:
                require(role in CHARACTERIZATION_ROLES, "Unknown case role")
                satisfied = True
            if not satisfied:
                fail("original_role_failed", "Original role requirement missing")
        require(deadline is None or time.monotonic() < deadline, "Qualification deadline")
    except (ValueError, KeyError, TypeError, IndexError, OverflowError) as error:
        fail("evidence_invalid", str(error))
    witnesses = copy.deepcopy(crop["witnesses"]) if crop else []
    for witness in witnesses:
        keys = (
            "case_id",
            "look",
            "through_batch",
            "identity",
            "row_sha256",
            "prefix_sha256",
            "crop_record_sha256",
        )
        p = provenance[witness["look"] - 1]
        if isinstance(p, dict) and all(k in p for k in keys):
            witness["prefix_binding"] = {k: copy.deepcopy(p[k]) for k in keys}
        else:
            witness["prefix_binding"] = None
            fail("evidence_invalid", "Unbound witness")
    coverage = {
        "final_eligible_statistics": [
            t["id"] for t in history[-1]["tests"] if t.get("eligible") is True
        ]
        if history
        else [],
        "limitations": (copy.deepcopy(crop["support_limitations"]) if crop else [])
        + native_limitations,
    }
    execution_valid = set(receipts) == set(RECEIPTS) and all(receipts[k] is True for k in RECEIPTS)
    evidence_valid = "evidence_invalid" not in failures and "numerically_unresolved" not in failures
    outcome = (
        "detected"
        if seen
        else "budget_nondetection"
        if final_eligible and evidence_valid
        else "not_evaluable"
    )
    return {
        "schema": "dudect-role-assessment/3",
        "role": role,
        "execution_valid": execution_valid,
        "evidence_valid": evidence_valid,
        "statistical_outcome": outcome,
        "coverage": coverage,
        "role_requirement_satisfied": not failures,
        "sensitivity_requirement_satisfied": (not failures) if positive else None,
        "original_result": {
            "contract_id": "original-native-role",
            "result": copy.deepcopy(original_role),
        },
        "effective_result": {
            "contract_sha256": CONTRACT_SHA256,
            "requirement_satisfied": not failures,
        },
        "contract_sha256": CONTRACT_SHA256,
        "case_id": case_id,
        "profile": profile,
        "detection_requirement_satisfied": crop["detection_requirement_satisfied"]
        if positive and crop
        else False
        if positive
        else None,
        "qualification_passed": not failures,
        "all_final_statistics_eligible": final_eligible,
        "final_raw0_101_eligible": raw_stats,
        "raw_floor_met": raw_floor,
        "support_limitations": copy.deepcopy(crop["support_limitations"]) if crop else [],
        "native_support_limitations": native_limitations,
        "witnesses": witnesses,
        "first_witness": witnesses[0] if witnesses else None,
        "original_role_result": copy.deepcopy(original_role),
        "numeric_unresolved_ever": numeric,
        "presignal_detections": pre,
        "failures": sorted(failures),
        "failure_details": details,
        "evidence_status": "verified_input" if not failures else "failed",
        "adopted": False,
    }
