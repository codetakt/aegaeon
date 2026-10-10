"""Per-case monitoring requirements; successful characterization is not secrecy."""

from __future__ import annotations

from typing import Any

from dudect_candidate import ALPHA, CANDIDATE_CASES, NUMERICAL_SHA256, validate_candidate_report
from dudect_results import NONDETECTION, PROFILES
from dudect_support import require

CONTRACT_COMPLETE = "observation_contract_satisfied"
POSITIVE_STATISTICS = {"control_mean_shift": 0, "control_variance_shift": 101}
NONDETECTION_ROLES = {"measurement_negative_control", "protected_input_observation"}
CHARACTERIZATION_ROLES = {
    "authentication_result_characterization",
    "public_fixture_characterization",
}


class ObservationError(ValueError):
    """A valid, completed observation did not meet its statistical requirement."""


def require_observation(condition: bool, message: str) -> None:
    if not condition:
        raise ObservationError(message)


def contract_roles(contract: Any) -> dict[str, str]:
    require(isinstance(contract, dict), "Observation contract required")
    require(
        contract.get("schema") == "dudect-case-contract-candidate/2", "Unknown contract revision"
    )
    require(
        contract["numerical_candidate"]["implementation_sha256"] == NUMERICAL_SHA256,
        "Unreviewed numerical implementation",
    )
    cases = contract.get("cases")
    require(isinstance(cases, list), "Contract case inventory required")
    expected = {f"{suite}/{name}" for suite, names in CANDIDATE_CASES.items() for name in names}
    roles = {case["stable_id"]: case["proposed_role"] for case in cases}
    require(len(cases) == len(roles) and set(roles) == expected, "Contract case inventory mismatch")
    require(
        all(
            role in NONDETECTION_ROLES | CHARACTERIZATION_ROLES | {"measurement_positive_control"}
            for role in roles.values()
        ),
        "Unknown observation role",
    )
    return roles


def assess_case(
    case_id: str, role: str, history: list[dict[str, Any]], profile: str
) -> dict[str, Any]:
    final = history[-1]
    require(final["collection_complete"], f"Incomplete schedule: {case_id}")
    require_observation(
        min(final["raw_class_counts"]) >= PROFILES[profile][1],
        f"Raw class floor not reached: {case_id}",
    )
    outcome = final["candidate_statistical_outcome"]
    name = case_id.split("/")[1]
    if role in NONDETECTION_ROLES:
        require_observation(outcome == NONDETECTION, f"{case_id}: {outcome}")
        requirement = "complete_nondetection"
    elif role == "measurement_positive_control":
        require(name in POSITIVE_STATISTICS, "Unknown positive control")
        statistic = POSITIVE_STATISTICS[name]
        require_observation(
            any(row["tests"][statistic].get("p", 1) < ALPHA for row in history),
            f"Required control statistic {statistic} not detected: {case_id}",
        )
        requirement = f"positive_control_statistic_{statistic}"
    else:
        require(role in CHARACTERIZATION_ROLES, f"Unknown observation role: {role}")
        requirement = "full_fixture_characterization"
    return {
        "case_id": case_id,
        "role": role,
        "requirement": requirement,
        "statistical_outcome": outcome,
        "requirement_satisfied": True,
        "product_assurance": "not_established",
    }


def assess_collection(
    collection: Any, expected: dict[str, Any], contract: dict[str, Any]
) -> list[dict[str, Any]]:
    decisions = validate_candidate_report(collection, expected)
    roles = contract_roles(contract)
    suite, profile = collection["suite"], collection["profile"]
    assessment = []
    for name in CANDIDATE_CASES[suite]:
        history = [row for row in decisions if row["case"] == name]
        case_id = f"{suite}/{name}"
        assessment.append(assess_case(case_id, roles[case_id], history, profile))
    return assessment
