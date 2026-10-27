"""Derived failure diagnostics; these summaries never admit an observation."""

from __future__ import annotations

from typing import Any

from dudect_candidate import CandidateAdmission, significant
from dudect_contract import ObservationError, assess_case
from dudect_support import require


def summarize_case(
    observations: list[dict[str, Any]],
    binding: dict[str, str],
    role: str,
    verified_history: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    name = binding["case_id"].split("/")[1]
    admission = CandidateAdmission(name, binding["profile"], binding=binding)
    original = [admission.admit(row) for row in observations]
    history = original if verified_history is None else verified_history
    require(len(history) == len(original), "Verified history length mismatch")
    failure = None
    try:
        assess_case(binding["case_id"], role, history, binding["profile"])
    except ObservationError as error:
        failure = str(error)
    looks = []
    previous = [[0, 0] for _ in history[0]["tests"]]
    for observation, decision in zip(observations, history, strict=True):
        counts = [values[:2] for values in observation["statistics"]]
        looks.append(
            {
                "look": observation["look"],
                "measured_batches": observation["batches"],
                "raw_class_counts": decision["raw_class_counts"],
                "retained_counts_since_previous_look": [
                    [pair[group] - old[group] for group in (0, 1)]
                    for pair, old in zip(counts, previous, strict=True)
                ],
                "detected_statistics": [test for test in decision["tests"] if significant(test)],
                "ineligible_statistics": [
                    {
                        **test,
                        "class_counts": counts[test["id"]],
                        "means": observation["statistics"][test["id"]][2:4],
                        "squared_deviations": observation["statistics"][test["id"]][4:6],
                        "native_support": observation["support"][test["id"]],
                    }
                    for test in decision["tests"]
                    if not test["eligible"]
                ],
            }
        )
        previous = counts
    return {
        "binding": binding,
        "role": role,
        "requirement_satisfied": failure is None,
        "failure": failure,
        "statistical_outcome": history[-1]["candidate_statistical_outcome"],
        "pilot": observations[0]["pilot"],
        "looks": looks,
    }


def summarize_collection(
    cases: dict[str, Any],
    bindings: dict[str, Any],
    roles: dict[str, str],
    verified_histories: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": "dudect-diagnostic-summary/1",
        "admission": "inactive",
        "collection_complete": set(cases) == set(bindings),
        "uncompleted_cases": [
            binding["case_id"] for name, binding in bindings.items() if name not in cases
        ],
        "cases": {
            name: summarize_case(
                rows,
                bindings[name],
                roles[bindings[name]["case_id"]],
                None if verified_histories is None else verified_histories[name],
            )
            for name, rows in cases.items()
        },
    }
