"""Experimental PR-only inference; never changes an adopted gate or old verdict."""

from __future__ import annotations

import itertools
import math
from collections import Counter
from fractions import Fraction
from typing import Any

from dudect_candidate import ALPHA, BASE_NUMERICAL_SHA256, NUMERICAL_SHA256, canonical, digest
from dudect_results import BATCH_SIZE, CANDIDATE_PROFILES
from dudect_support import require

BASE_NUMERICAL = "594123236e82350f69e907ae16825028201cd06a31f5df820b6ec46d1e77f279"
BASE_CONTRACT = "c44d1ac1ef801e229448960e57e90b2851be819cd449492a5500000996c97ca6"
REVIEWED = canonical(
    {
        "base_numerical_sha256": BASE_NUMERICAL,
        "base_contract_sha256": BASE_CONTRACT,
        "profile": "pr",
        "looks": [1, 2, 3, 4, 5, 6, 7, 16],
        "batch_size": 65536,
        "excluded_per_batch": 11,
        "minimum_class_count": 10001,
        "raw_class_floor": 200000,
        "deadline_seconds": 900,
        "alpha_ratio": [5511632216234413, 9444732965739290427392],
    }
)
POLICY = {
    "schema": "dudect-pr-sparse-reanalysis/1",
    "reviewed_settings_sha256": digest(REVIEWED),
    "exceptions": [2, 3],
    "base_reason": "degenerate_variance",
    "statistic": "absolute_mean_difference_inclusive_exact_tail",
    "square_collision": "unsupported",
    "existing_decisions": "preserved_with_separate_supplement",
    "status": "experimental_not_adopted",
    "premise": "conditional_uniform_label_allocation_not_established_by_arithmetic",
}
POLICY_SHA256 = digest(canonical(POLICY))


def settings(binding: dict[str, Any], profile: str) -> dict[str, Any]:
    # The native/new binding is authenticated before mapping to reviewed base settings.
    if binding["numerical_sha256"] == NUMERICAL_SHA256:
        from dudect_sparse_contract import check_runtime_contract  # noqa: PLC0415

        require(
            binding["contract_sha256"] == check_runtime_contract(), "Wrong sparse contract binding"
        )
        binding = {**binding, "numerical_sha256": BASE_NUMERICAL, "contract_sha256": BASE_CONTRACT}
    looks, floor, deadline = CANDIDATE_PROFILES[profile]
    return {
        "base_numerical_sha256": binding["numerical_sha256"],
        "base_contract_sha256": binding["contract_sha256"],
        "profile": profile,
        "looks": list(looks),
        "batch_size": BATCH_SIZE,
        "excluded_per_batch": 11,
        "minimum_class_count": 10001,
        "raw_class_floor": floor,
        "deadline_seconds": deadline,
        "alpha_ratio": list(ALPHA.as_integer_ratio()),
    }


def falling(n: int, r: int) -> int:
    return math.prod(range(n - r + 1, n + 1)) if 0 <= r <= n else 0


def validate_histograms(histograms: list[dict[int, int]]) -> None:
    require(len(histograms) == 2, "Two class histograms required")
    for histogram in histograms:
        require(isinstance(histogram, dict), "Histogram required")
        require(
            all(
                type(t) is int and 0 <= t < 2**63 and type(n) is int and n > 0
                for t, n in histogram.items()
            ),
            "Invalid native histogram multiplicity or tick",
        )


def exact_tail(histograms: list[dict[int, int]], values: dict[int, Fraction]) -> dict[str, Any]:
    """At most three exceptions, including small fixtures for independent enumeration."""
    validate_histograms(histograms)
    counts = [sum(h.values()) for h in histograms]
    require(min(counts) > 0, "Empty class")
    pooled = Counter(histograms[0]) + Counter(histograms[1])
    require(set(values) == set(pooled), "Incomplete transformed support")
    mode = min(pooled, key=lambda t: (-pooled[t], t))
    rare = sorted((t, n) for t, n in pooled.items() if t != mode)
    r = sum(n for _, n in rare)
    require(r <= 3, "Exact kernel exceeds three exceptions")
    n0, n1 = counts
    total = n0 + n1
    deviations = {t: v - values[mode] for t, v in values.items()}
    pooled_sum = sum(deviations[t] * n for t, n in pooled.items())
    actual_sum = sum(deviations[t] * n for t, n in histograms[0].items())
    observed = abs(total * actual_sum - n0 * pooled_sum)
    denominator = falling(total, r)
    numerator = mass = states = 0
    for allocation in itertools.product(*(range(n + 1) for _, n in rare)):
        k = sum(allocation)
        weight = falling(n0, k) * falling(n1, r - k)
        weight *= math.prod(math.comb(n, a) for (_, n), a in zip(rare, allocation, strict=True))
        allocated = sum(deviations[t] * a for (t, _), a in zip(rare, allocation, strict=True))
        mass += weight
        states += 1
        if abs(total * allocated - n0 * pooled_sum) >= observed:
            numerator += weight
    require(mass == denominator and states <= 8, "Invalid exact probability mass")
    p = Fraction(numerator, denominator)
    return {
        "p_exact": [p.numerator, p.denominator],
        "exceptions": r,
        "pooled_mode": mode,
        "allocation_states": states,
    }


def supplement(  # noqa: PLR0911 - preserve an explicit reason at each domain boundary
    original: dict[str, Any],
    histograms: list[dict[int, int]],
    index: int,
    center: float,
    configuration: dict[str, Any],
) -> dict[str, Any]:
    """Return a separate result. Unsupported settings/data never replace the base result."""
    unchanged = {"applied": False}
    if canonical(configuration) != REVIEWED or BASE_NUMERICAL_SHA256 != BASE_NUMERICAL:
        return {**unchanged, "reason": "unreviewed_configuration"}
    if original.get("eligible") is not False or original.get("reason") != "degenerate_variance":
        return {**unchanged, "reason": "base_result_preserved"}
    validate_histograms(histograms)
    counts = [sum(h.values()) for h in histograms]
    maximum = configuration["looks"][-1] * (configuration["batch_size"] - 11)
    require(sum(counts) <= maximum, "Histogram exceeds reviewed PR budget")
    if min(counts) < configuration["minimum_class_count"]:
        return {**unchanged, "reason": "insufficient_count"}
    pooled = Counter(histograms[0]) + Counter(histograms[1])
    exceptions = sum(counts) - max(pooled.values())
    if exceptions not in (2, 3):
        return {**unchanged, "reason": "outside_two_three_exception_domain"}
    if any(t >= 2**53 for t in pooled):
        return {**unchanged, "reason": "unsupported_tick_representation"}
    require(type(index) is int and 0 <= index < 102, "Invalid statistic index")
    require(math.isfinite(center) and center >= 0, "Invalid fixed center")
    converted = {
        t: ((float(t) - center) * (float(t) - center) if index == 101 else float(t)) for t in pooled
    }
    if not all(math.isfinite(v) for v in converted.values()):
        return {**unchanged, "reason": "unsupported_transform_range"}
    if len(set(converted.values())) != len(converted):
        return {**unchanged, "reason": "transform_collision"}
    lower = Fraction(falling(10001, exceptions), falling(maximum, exceptions))
    alpha = Fraction(*configuration["alpha_ratio"])
    if lower < alpha:
        return {**unchanged, "reason": "lower_bound_not_sufficient"}
    result = exact_tail(histograms, {t: Fraction(v) for t, v in converted.items()})
    p = Fraction(*result["p_exact"])
    require(p >= lower >= alpha, "Exact tail contradicts reviewed non-rejection bound")
    return {
        "applied": True,
        "policy_sha256": POLICY_SHA256,
        "decision": {
            "id": index,
            "eligible": True,
            "method": POLICY["schema"],
            "n0": counts[0],
            "n1": counts[1],
            "p": float(p),
            "alpha": ALPHA,
            **result,
        },
        "lower_bound_exact": [lower.numerator, lower.denominator],
        "alpha_exact": configuration["alpha_ratio"],
        "transformed_values": [
            [t, *Fraction(v).as_integer_ratio()] for t, v in sorted(converted.items())
        ],
        "histograms": [[[t, n] for t, n in sorted(h.items())] for h in histograms],
    }
