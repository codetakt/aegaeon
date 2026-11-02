"""Separate PR four-exception non-rejection policy for original populations only."""

from __future__ import annotations

import copy
import itertools
import math
from collections import Counter
from fractions import Fraction
from typing import Any

from dudect_candidate import ALPHA, BASE_NUMERICAL_SHA256, canonical, digest, significant
from dudect_sparse import BASE_NUMERICAL, REVIEWED, falling, settings, validate_histograms
from dudect_sparse_replay import check_moments
from dudect_support import require

POLICY = {
    "schema": "dudect-pr-four-exception-bound/1",
    "reviewed_settings_sha256": digest(REVIEWED),
    "exceptions": [4],
    "base_reason": "degenerate_variance",
    "statistic": "absolute_mean_difference_inclusive_exact_tail",
    "lower_bound": "falling(min(n0,n1),4)/falling(n0+n1,4)",
    "condition": "lower_bound>=exact_binary64_alpha",
    "square_collision": "unsupported",
    "scope": "original native populations only; no distributed crops",
    "existing_decisions": "preserved_with_separate_supplement",
    "status": "experimental_not_adopted",
    "premise": "conditional_uniform_label_allocation_not_established_by_arithmetic",
}
POLICY_SHA256 = digest(canonical(POLICY))


def exact_tail(histograms: list[dict[int, int]], values: dict[int, Fraction]) -> dict[str, Any]:
    """At most four exceptions, including small fixtures for independent enumeration."""
    validate_histograms(histograms)
    counts = [sum(h.values()) for h in histograms]
    require(min(counts) > 0, "Empty class")
    pooled = Counter(histograms[0]) + Counter(histograms[1])
    require(set(values) == set(pooled), "Incomplete transformed support")
    mode = min(pooled, key=lambda t: (-pooled[t], t))
    rare = sorted((t, n) for t, n in pooled.items() if t != mode)
    r = sum(n for _, n in rare)
    require(r <= 4, "Exact kernel exceeds four exceptions")
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
    require(mass == denominator and states <= 16, "Invalid exact probability mass")
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
    if exceptions != 4:
        return {**unchanged, "reason": "outside_four_exception_domain"}
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
    lower = Fraction(falling(min(counts), exceptions), falling(sum(counts), exceptions))
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


def augment(row, tests, prefix, *, excluded=()):
    """Verify complete current-prefix support before adding any certificate."""
    prefix.check_row(row)
    effective = copy.deepcopy(tests)
    receipts = []
    configuration = settings(row["binding"], row["profile"])
    for index, test in enumerate(tests):
        require(test["id"] == index, "Invalid test inventory")
        if (
            index in excluded
            or test.get("eligible") is not False
            or test.get("reason") != "degenerate_variance"
        ):
            continue
        # Four exceptions imply at most five native values. Endpoints come from
        # the complete histograms, never from only native min/max evidence.
        if any(end > 5 for end in prefix.endpoints(row, index)):
            receipts.append(
                {"statistic": index, "applied": False, "reason": "outside_four_exception_domain"}
            )
            continue
        histograms = prefix.selected(row, index)
        for group, histogram in enumerate(histograms):
            check_moments(histogram, row, index, group)
        addition = supplement(test, histograms, index, row["pilot"]["center"], configuration)
        receipts.append({"statistic": index, **addition})
        if addition["applied"]:
            effective[index] = addition["decision"]
    require(
        [t["id"] for t in tests if significant(t)]
        == [t["id"] for t in effective if significant(t)],
        "Four-exception supplement changed a detection",
    )
    return effective, receipts
