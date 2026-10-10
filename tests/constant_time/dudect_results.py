"""Strict version 2 observation admission, shared by both runtime entry points."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, NoReturn

SCHEMA_VERSION = 2
BATCH_SIZE = 65_536
STATISTICS = 102
ALPHA = 0.01 / (11 * STATISTICS * 8)
LEGACY_CASES = ("compare", "hmac", "ed25519", "rsa", "jwe")
NIX_CASES = ("ct_eq_32", "ct_eq_64", "ct_eq_128", "sha256", "hmac_sha256", "ed25519_verify")
PROFILES = {
    "pr": (tuple(range(1, 8)), 200_000, 900),
    "periodic": ((1, 2, 4, 8, 16, 32, 64, 98), 3_200_000, 7200),
}
NONDETECTION = "no_leakage_detected_within_budget"


def invalid(message: str) -> NoReturn:
    raise ValueError(message)


def beta_fraction(a: float, b: float, x: float) -> float:
    """Modified Lentz continued fraction for the regularized incomplete beta."""
    tiny = 1e-300
    c = 1.0
    d = 1 - (a + b) * x / (a + 1)
    d = 1 / (d if abs(d) > tiny else tiny)
    result = d
    for iteration in range(1, 10_001):
        even = 2 * iteration
        for numerator in (
            iteration * (b - iteration) * x / ((a + even - 1) * (a + even)),
            -(a + iteration) * (a + b + iteration) * x / ((a + even) * (a + even + 1)),
        ):
            d = 1 + numerator * d
            c = 1 + numerator / c
            d = 1 / (d if abs(d) > tiny else tiny)
            c = c if abs(c) > tiny else tiny
            delta = d * c
            result *= delta
        if abs(delta - 1) < 3e-14:
            return result
    invalid("Student-t tail did not converge")


def student_tail(t: float, degrees: float) -> float:
    """Two-sided Student-t probability, retaining fractional Welch degrees."""
    if not math.isfinite(t) or not math.isfinite(degrees) or degrees <= 0:
        invalid("Invalid Student-t inputs")
    ratio = abs(t) / math.sqrt(degrees)
    squared = ratio * ratio
    x = 1 / (1 + squared)
    y = squared / (1 + squared)
    if x == 0:
        return 0.0
    if y == 0:
        return 1.0
    a, b = degrees / 2, 0.5
    factor = math.exp(
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(y)
    )
    probability = (
        factor * beta_fraction(a, b, x) / a
        if x < (a + 1) / (a + b + 2)
        else 1 - factor * beta_fraction(b, a, y) / b
    )
    if not math.isfinite(probability) or not 0 <= probability <= 1:
        invalid("Invalid computed Student-t probability")
    return probability


def integer(value: Any) -> int:
    if type(value) is not int or value < 0:
        invalid("Expected nonnegative integer observation count")
    return value


def number(value: Any) -> float:
    if type(value) not in (float, int) or not math.isfinite(value):
        invalid("Expected finite observation statistic")
    return float(value)


def welch(values: list[Any]) -> dict[str, Any]:
    if len(values) != 6:
        invalid("Expected two counts, means and sums of squared deviations")
    n0, n1 = (integer(value) for value in values[:2])
    mean0, mean1, m20, m21 = (number(value) for value in values[2:])
    if min(mean0, mean1, m20, m21) < 0:
        invalid("Negative timing mean or squared deviation")
    if min(n0, n1) <= 10_000:
        return {"eligible": False, "reason": "insufficient_count"}
    v0, v1 = m20 / (n0 - 1), m21 / (n1 - 1)
    s0, s1 = v0 / n0, v1 / n1
    if min(v0, v1) <= 0 or not math.isfinite(s0 + s1) or s0 + s1 <= 0:
        return {"eligible": False, "reason": "degenerate_variance"}
    t = (mean0 - mean1) / math.sqrt(s0 + s1)
    denominator = s0 * s0 / (n0 - 1) + s1 * s1 / (n1 - 1)
    if denominator <= 0:
        invalid("Undefined Welch degrees of freedom")
    degrees = (s0 + s1) ** 2 / denominator
    p = student_tail(t, degrees)
    return {
        "eligible": True,
        "n0": n0,
        "n1": n1,
        "variance0": v0,
        "variance1": v1,
        "t": t,
        "degrees": degrees,
        "p": p,
        "alpha": ALPHA,
    }


@dataclass
class CaseAdmission:
    name: str
    profile: str
    previous: dict[str, Any] | None = None
    next_look: int = 0

    def validate_header(self, data: Any) -> None:
        looks, _, _ = PROFILES[self.profile]
        expected_keys = {
            "schema_version",
            "case",
            "profile",
            "batch_size",
            "batches",
            "look",
            "executed",
            "warmup",
            "rejected",
            "pilot",
            "statistics",
        }
        if not isinstance(data, dict) or set(data) != expected_keys:
            invalid("Invalid version 2 dudect observation shape")
        if self.next_look >= len(looks):
            invalid("Unexpected additional statistical inspection")
        expected = {
            "schema_version": SCHEMA_VERSION,
            "case": self.name,
            "profile": self.profile,
            "batch_size": BATCH_SIZE,
            "batches": looks[self.next_look],
            "look": self.next_look + 1,
            "executed": (looks[self.next_look] + 1) * BATCH_SIZE,
            "warmup": BATCH_SIZE,
        }
        for key, value in expected.items():
            if type(data[key]) is not type(value) or data[key] != value:
                invalid(f"Unexpected dudect {key}: {data[key]!r}")

    def pilot(self, data: dict[str, Any]) -> None:
        pilot = data["pilot"]
        if not isinstance(pilot, dict) or set(pilot) != {"count", "center", "cutoffs"}:
            invalid("Invalid pilot calibration")
        if not 0 < integer(pilot["count"]) <= BATCH_SIZE - 11 or number(pilot["center"]) < 0:
            invalid("Invalid pilot observations")
        cutoffs = pilot["cutoffs"]
        if not isinstance(cutoffs, list) or len(cutoffs) != STATISTICS - 2:
            invalid("Incomplete pilot cutoffs")
        counts = [integer(value) for value in cutoffs]
        if counts != sorted(counts):
            invalid("Unordered pilot cutoffs")
        if self.previous and pilot != self.previous["pilot"]:
            invalid("Pilot calibration changed during collection")

    def statistics(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        stats = data["statistics"]
        if not isinstance(stats, list) or len(stats) != STATISTICS:
            invalid("Incomplete dudect statistical inventory")
        decisions = []
        for index, values in enumerate(stats):
            if not isinstance(values, list):
                invalid("Invalid dudect statistic")
            decision = welch(values)
            for group in (0, 1):
                if values[group] > stats[0][group]:
                    invalid("Transformed count exceeds raw count")
                if self.previous and values[group] < self.previous["statistics"][index][group]:
                    invalid("Observation counts regressed")
            decisions.append({"id": index, **decision})
        return decisions

    def accounting(self, data: dict[str, Any]) -> int:
        rejected = integer(data["rejected"])
        stats = data["statistics"]
        raw_count = integer(stats[0][0]) + integer(stats[0][1])
        if raw_count + rejected != data["batches"] * (BATCH_SIZE - 11):
            invalid("Raw observation accounting mismatch")
        if stats[-1][:2] != stats[0][:2]:
            invalid("Second-order observation accounting mismatch")
        if self.previous and rejected < self.previous["rejected"]:
            invalid("Rejected observation count regressed")
        return raw_count

    def outcome(self, data: dict[str, Any], decisions: list[dict[str, Any]]) -> str:
        looks, minimum, _ = PROFILES[self.profile]
        final = self.next_look + 1 == len(looks)
        if any(test["eligible"] and test["p"] < ALPHA for test in decisions):
            result = "leakage_detected"
        elif not final:
            result = "collecting"
        elif min(data["statistics"][0][:2]) < minimum or not all(t["eligible"] for t in decisions):
            result = "inconclusive"
        else:
            result = NONDETECTION
        return result

    def admit(self, data: Any) -> dict[str, Any]:
        self.validate_header(data)
        self.pilot(data)
        decisions = self.statistics(data)
        raw_count = self.accounting(data)
        outcome = self.outcome(data, decisions)
        self.previous = data
        self.next_look += 1
        return {
            "case": self.name,
            "profile": self.profile,
            "look": self.next_look,
            "outcome": outcome,
            "raw_count": raw_count,
            "tests": decisions,
        }


def validate_case(name: str, profile: str, observations: Any) -> None:
    admission = CaseAdmission(name, profile)
    outcome = "inconclusive"
    if not isinstance(observations, list):
        invalid("Expected case observation history")
    for observation in observations:
        result = admission.admit(observation)
        outcome = result["outcome"]
        if outcome not in ("collecting", NONDETECTION):
            invalid(f"dudect {name}: {outcome}")
    if outcome != NONDETECTION:
        invalid(f"dudect {name}: incomplete measurement schedule")


def validate_report(report: Any) -> None:
    keys = {"schema_version", "suite", "profile", "outcome", "cases"}
    if not isinstance(report, dict) or set(report) != keys:
        invalid("A complete version 2 report is required")
    if type(report["schema_version"]) is not int or report["schema_version"] != SCHEMA_VERSION:
        invalid("A version 2 report with observed counts is required")
    if report.get("suite") not in ("legacy", "nix") or report.get("profile") not in (
        "pr",
        "periodic",
    ):
        invalid("Unknown dudect suite or profile")
    expected = LEGACY_CASES if report["suite"] == "legacy" else NIX_CASES
    cases = report.get("cases")
    if not isinstance(cases, dict) or set(cases) != set(expected):
        invalid("Incomplete dudect case inventory")
    for name in expected:
        validate_case(name, report["profile"], cases[name])
    if report.get("outcome") != NONDETECTION:
        invalid("Report does not admit the complete measurement profile")
