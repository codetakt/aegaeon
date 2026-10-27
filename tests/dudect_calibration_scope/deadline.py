# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I002
"""Counterfactual deadline review; never rewrite the historical screen."""

import copy
import json
from pathlib import Path

from analysis_contract import significant
from dudect_candidate import canonical, digest
from dudect_support import require
from screen import evaluate as old_evaluate

POLICY = json.loads((Path(__file__).parent / "deadline_contract.json").read_text())
POLICY_SHA256 = digest(canonical(POLICY))


def review(history, scope, role, crop1_counts=None):  # noqa: PLR0912, PLR0915 -- ordered evidence checks retain each rejection boundary
    if crop1_counts is not None:
        require(len(crop1_counts) == len(history), "Incomplete crop count history")
    old = old_evaluate(history, scope, role)
    candidate = copy.deepcopy(old)
    # Only the separately proposed detection deadline changes. All old validity,
    # final eligibility, no-presignal and retention failures survive.
    if scope in ("early", "late"):
        candidate["failures"] = [
            f for f in candidate["failures"] if f != "required_crop1_signal_not_detected"
        ]
    detected, eligible, counted = [], [], []
    seen = set()
    counts_complete = True
    for index, row in enumerate(history):
        require([t["id"] for t in row["tests"]] == list(range(102)), "Invalid statistic inventory")
        now = set(row["detected_now"])
        require(
            now == {t["id"] for t in row["tests"] if significant(t)},
            "Detection inventory differs from numerical decisions",
        )
        require(now <= set(row["detected_ever"]), "Current detection lost")
        if not seen <= set(row["detected_ever"]):
            candidate["failures"].append("prior_detection_lost")
        seen.update(now)
        test = row["tests"][1]
        pair = crop1_counts[index] if crop1_counts is not None else [test.get("n0"), test.get("n1")]
        if test["eligible"] and crop1_counts is not None:
            require(pair == [test["n0"], test["n1"]], "Count evidence differs from eligible test")
        counts_complete &= all(n is not None for n in pair)
        if all(n is not None for n in pair) and min(pair) > 10000:
            counted.append(row["look"])
        if test["eligible"]:
            eligible.append(row["look"])
        if 1 in now:
            require(test["eligible"], "Ineligible detection cannot satisfy deadline")
            detected.append(row["look"])
    if scope in ("early", "late") and not detected:
        candidate["failures"].append("required_crop1_signal_not_detected_within_budget")
    candidate["passed"] = not candidate["failures"]
    final = history[-1] if history else None
    return {
        "policy_sha256": POLICY_SHA256,
        "status": "counterfactual_not_adopted",
        "historical_rule_on_supplied_history": old,
        "fixed_budget_candidate": candidate,
        "counts_complete": counts_complete,
        "first_crop1_count_sufficient_look": min(counted, default=None)
        if counts_complete
        else None,
        "first_crop1_eligible_look": min(eligible, default=None),
        "first_crop1_detection_look": min(detected, default=None),
        "detected_within_early_window": any(x <= 7 for x in detected),
        "final_crop1_eligible": final["tests"][1]["eligible"] if final else False,
        "final_outcome": final["candidate_statistical_outcome"] if final else None,
    }
