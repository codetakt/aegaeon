"""Version 4 candidate collection with explicit discrete-support inference."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from dudect_process import ObservationStream, load_json
from dudect_results import (
    BATCH_SIZE,
    LEGACY_CASES,
    NIX_CASES,
    NONDETECTION,
    PROFILES,
    STATISTICS,
    CaseAdmission,
    integer,
)
from dudect_support import require, validate_support

CONTROL_CASES = ("control_independent", "control_mean_shift", "control_variance_shift")
CANDIDATE_CASES = {
    "legacy": (
        *LEGACY_CASES,
        "compare_product_32",
        "hmac_key_reject",
        "jwe_key_reject",
        *CONTROL_CASES,
    ),
    "nix": (*NIX_CASES, "hmac_sha256_key", *CONTROL_CASES),
}
ALPHA = 0.01 / (21 * STATISTICS * 8)
COLLECTION_COMPLETE = "candidate_collection_complete"
BINDING_KEYS = {"case_id", "profile", "contract_sha256", "build_sha256", "numerical_sha256"}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


NUMERICAL_PARAMETERS = {
    "schema": 4,
    "case_executions": 21,
    "statistics": STATISTICS,
    "alpha": ALPHA,
    "batch": BATCH_SIZE,
    "profiles": PROFILES,
    "crop": "tick <= disjoint_pilot_quantile",
    "degenerate": "exact_absolute_mean_permutation_identical_native_ticks_counts_gt10000",
    "continuous": "fractional_df_welch_positive_variance",
    "timer": "mfence_lfence_rdtsc_lfence_requires_execution_serialization",
}
NUMERICAL_SHA256 = digest(canonical(NUMERICAL_PARAMETERS))


def sha256(value: Any) -> None:
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
        "Invalid SHA-256 identity",
    )


def validate_binding(binding: Any, name: str, profile: str) -> None:
    require(isinstance(binding, dict) and set(binding) == BINDING_KEYS, "Invalid binding shape")
    require(
        isinstance(binding["case_id"], str)
        and any(
            binding["case_id"] == f"{suite}/{name}" and name in names
            for suite, names in CANDIDATE_CASES.items()
        ),
        "Wrong case binding",
    )
    require(binding["profile"] == profile and profile in PROFILES, "Wrong profile binding")
    require(binding["numerical_sha256"] == NUMERICAL_SHA256, "Wrong numerical contract")
    for key in ("contract_sha256", "build_sha256"):
        sha256(binding[key])


def input_audit(data: dict[str, Any], previous: dict[str, Any] | None) -> None:
    audit = data["input_audit"]
    keys = {"class_count", "key_draws", "key_excluded"}
    require(isinstance(audit, dict) and set(audit) == keys, "Missing input audit")
    for key in keys:
        require(isinstance(audit[key], list) and len(audit[key]) == 2, "Invalid class audit")
        for group, value in enumerate(audit[key]):
            integer(value)
            if previous:
                require(value >= previous["input_audit"][key][group], "Input audit regressed")
    require(sum(audit["class_count"]) == data["executed"], "Prepared input count mismatch")
    for group in (0, 1):
        require(
            audit["class_count"][group] >= data["statistics"][0][group],
            "Input class count mismatch",
        )
        draws, excluded = audit["key_draws"][group], audit["key_excluded"][group]
        if data["case"] in ("hmac_key_reject", "jwe_key_reject"):
            require(
                draws - excluded == audit["class_count"][group], "Key-domain accounting mismatch"
            )
            require(draws <= 128 * audit["class_count"][group], "Key draw budget exceeded")
            if group == 0:
                require(excluded == 0, "Fixed rejection key was excluded")
        else:
            require(draws == 0 and excluded == 0, "Unexpected key-domain audit")


@dataclass
class CandidateAdmission(CaseAdmission):
    binding: dict[str, str] = field(default_factory=dict)
    detected: bool = False

    def admit(self, data: Any) -> dict[str, Any]:
        require(isinstance(data, dict), "Candidate observation required")
        require(
            type(data.get("schema_version")) is int and data["schema_version"] == 4,
            "Version 4 candidate required; historical reports are not convertible",
        )
        validate_binding(self.binding, self.name, self.profile)
        require(data.get("binding") == self.binding, "Candidate identity mismatch")
        require({"support", "input_audit"} <= set(data), "Native support and input audit required")
        # Reuse arithmetic checks only after authenticating the version4 envelope.
        counters = {k: v for k, v in data.items() if k not in ("binding", "support", "input_audit")}
        counters["schema_version"] = 2
        self.validate_header(counters)
        self.pilot(counters)
        singleton = validate_support(data, self.previous)
        decisions = self.statistics(counters)
        for index in singleton:
            # Native integer extrema and moments were validated above. Every
            # label permutation then has absolute mean difference zero.
            decisions[index] = {
                "id": index,
                "eligible": True,
                "p": 1.0,
                "method": "exact_absolute_mean_permutation_identical_native_support",
                "n0": counters["statistics"][index][0],
                "n1": counters["statistics"][index][1],
            }
        raw_count = self.accounting(counters)
        input_audit(data, self.previous)
        for decision in decisions:
            if decision["eligible"]:
                decision["alpha"] = ALPHA
        self.detected |= any(d["eligible"] and d["p"] < ALPHA for d in decisions)
        self.next_look += 1
        final = self.next_look == len(PROFILES[self.profile][0])
        outcome = "collecting"
        if self.detected:
            outcome = "leakage_detected"
        elif final:
            enough = min(data["statistics"][0][:2]) >= PROFILES[self.profile][1]
            outcome = (
                NONDETECTION if enough and all(d["eligible"] for d in decisions) else "inconclusive"
            )
        self.previous = data
        return {
            "case": self.name,
            "profile": self.profile,
            "look": self.next_look,
            "candidate_statistical_outcome": outcome,
            "collection_complete": final,
            "admission": "inactive",
            "raw_count": raw_count,
            "raw_class_counts": counters["statistics"][0][:2],
            "tests": decisions,
            "identical_native_tick_candidates": singleton,
            "degenerate_inference": "certified_identical_native_support_only",
        }


@dataclass
class CandidateStream(ObservationStream):
    bindings: dict[str, dict[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require(
            bool(self.cases) and set(self.bindings) == set(self.cases), "Case bindings required"
        )
        self.histories = {name: [] for name in self.cases}
        self.admission = CandidateAdmission(
            self.cases[0], self.profile, binding=self.bindings[self.cases[0]]
        )

    def observe(self, line: bytes) -> None:
        require(self.index < len(self.cases), "Unexpected extra candidate observation")
        data = load_json(line)
        name = self.cases[self.index]
        self.histories[name].append(data)
        result = self.admission.admit(data)
        self.decisions.append(result)
        if result["collection_complete"]:
            self.index += 1
            if self.index < len(self.cases):
                name = self.cases[self.index]
                self.admission = CandidateAdmission(name, self.profile, binding=self.bindings[name])


def validate_candidate_report(report: Any, expected: dict[str, Any]) -> list[dict[str, Any]]:
    require(
        isinstance(report, dict)
        and set(report)
        == {
            "schema_version",
            "suite",
            "profile",
            "outcome",
            "admission",
            "bindings",
            "binaries",
            "cases",
        },
        "Complete candidate report required",
    )
    require(
        type(report["schema_version"]) is int and report["schema_version"] == 4,
        "Wrong candidate version",
    )
    suite, profile = report["suite"], report["profile"]
    require(isinstance(suite, str) and suite in CANDIDATE_CASES, "Unknown candidate suite")
    require(isinstance(profile, str) and profile in PROFILES, "Unknown candidate profile")
    require(
        report["outcome"] == COLLECTION_COMPLETE and report["admission"] == "inactive",
        "Candidate evidence cannot claim gate acceptance",
    )
    require(
        isinstance(expected, dict) and set(expected) == {"bindings", "binaries"},
        "External bindings and binaries required",
    )
    require(
        report["bindings"] == expected["bindings"] and report["binaries"] == expected["binaries"],
        "Report/external artifact binding mismatch",
    )
    names = CANDIDATE_CASES[suite]
    for key in ("cases", "binaries", "bindings"):
        require(
            isinstance(report[key], dict) and set(report[key]) == set(names),
            "Incomplete candidate inventory",
        )
    validate_artifacts(expected, suite, profile)
    stream = CandidateStream(names, profile, bindings=expected["bindings"])
    for name in names:
        require(isinstance(report["cases"][name], list), "Case history required")
        for observation in report["cases"][name]:
            stream.observe(canonical(observation))
    stream.finish(0)
    return stream.decisions


def validate_artifacts(expected: dict[str, Any], suite: str, profile: str) -> None:
    for name in CANDIDATE_CASES[suite]:
        binding, binary = expected["bindings"][name], expected["binaries"][name]
        validate_binding(binding, name, profile)
        require(binding["case_id"] == f"{suite}/{name}", "Wrong suite binding")
        require(
            isinstance(binary, dict) and set(binary) == {"path", "sha256", "build_sha256"},
            "Invalid binary identity",
        )
        require(isinstance(binary["path"], str) and bool(binary["path"]), "Missing binary path")
        sha256(binary["sha256"])
        require(binary["build_sha256"] == binding["build_sha256"], "Wrong binary build binding")
