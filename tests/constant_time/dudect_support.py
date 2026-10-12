"""Strict native support validation for the inactive observation candidate."""

from __future__ import annotations

import math
import re
from typing import Any

from dudect_results import (
    BATCH_SIZE,
    CANDIDATE_PROFILES as PROFILES,
    STATISTICS,
    integer,
    invalid,
    number,
)

MAX_SUPPORT_COUNT = (BATCH_SIZE - 11) * max(profile[0][-1] for profile in PROFILES.values())


def require(condition: bool, message: str) -> None:
    if not condition:
        invalid(message)


def tick(value: Any) -> int:
    result = integer(value)
    require(result < 2**63, "Native tick exceeds int64")
    return result


def binary64(value: Any) -> float:
    require(isinstance(value, str), "Missing binary64 support")
    require(
        re.fullmatch(r"0x[0-9a-f]+(?:\.[0-9a-f]+)?p[+-][0-9]+", value) is not None,
        "Invalid binary64 encoding",
    )
    try:
        result = float.fromhex(value)
    except (OverflowError, ValueError):
        invalid("Invalid binary64 encoding")
    require(math.isfinite(result) and result >= 0, "Nonfinite or negative support")
    return result


def moment_bounds(count: int, minimum: float, maximum: float, mean: float, m2: float) -> None:
    """Necessary support bounds, padded for the native binary64 Welford update.

    See dudect-case-contract.md for the forward-error budget and its scope.
    This checks consistency; it never changes moments or computes a p-value.
    """
    span = math.nextafter(maximum - minimum, math.inf)
    unit = math.ulp(maximum)
    mean_error = 4 * count * unit
    delta_error = mean_error + unit
    expanded = span + delta_error
    error = math.nextafter(
        8
        * count
        * (
            span * delta_error
            + delta_error * delta_error
            + count * 2**-53 * expanded * expanded
            + math.ulp(0.0)
        ),
        math.inf,
    )
    require(math.isfinite(error), "Unbounded native moment rounding error")
    lower_mean = math.nextafter(minimum + span / count - mean_error, -math.inf)
    upper_mean = math.nextafter(maximum - span / count + mean_error, math.inf)
    require(lower_mean <= mean <= upper_mean, "Mean contradicts attained extrema")
    below, above = mean - minimum, maximum - mean
    lower = max(0.0, below - mean_error) ** 2 + max(0.0, above - mean_error) ** 2
    upper = count * (below + mean_error) * (above + mean_error)
    require(
        math.nextafter(lower - error, -math.inf) <= m2 <= math.nextafter(upper + error, math.inf),
        "Squared deviations contradict native support",
    )


def class_support(support: Any, count: int, mean: float, m2: float) -> None:
    keys = {
        "count",
        "tick_min",
        "tick_max",
        "tick_min_count",
        "tick_max_count",
        "value_min_hex",
        "value_max_hex",
    }
    require(isinstance(support, dict) and set(support) == keys, "Invalid native support")
    require(integer(support["count"]) == count, "Support count mismatch")
    require(count <= MAX_SUPPORT_COUNT, "Support count exceeds measurement budget")
    minimum_count, maximum_count = (
        integer(support[k]) for k in ("tick_min_count", "tick_max_count")
    )
    if not count:
        require(minimum_count == maximum_count == 0, "Empty support has endpoint counts")
        require(
            all(support[k] is None for k in keys - {"count", "tick_min_count", "tick_max_count"}),
            "Empty support has extrema",
        )
        require(mean == 0 and m2 == 0, "Empty class has moments")
        return
    low, high = tick(support["tick_min"]), tick(support["tick_max"])
    minimum, maximum = binary64(support["value_min_hex"]), binary64(support["value_max_hex"])
    require(low <= high and minimum <= maximum, "Reversed support")
    if low == high:
        require(minimum_count == maximum_count == count, "Singleton endpoint count mismatch")
    else:
        require(
            minimum_count > 0 and maximum_count > 0 and minimum_count + maximum_count <= count,
            "Invalid endpoint multiplicities",
        )
    require(minimum <= mean <= maximum, "Mean outside native support")
    if minimum == maximum:
        require(mean == minimum and m2 == 0, "Singleton support contradicts moments")
    else:
        require(m2 > 0 and count >= 2, "Distinct support contradicts moments")
        moment_bounds(count, minimum, maximum, mean, m2)


def transformed_support(
    index: int, support: dict[str, Any], raw: dict[str, Any], data: dict[str, Any]
) -> None:
    low, high = support["tick_min"], support["tick_max"]
    minimum, maximum = binary64(support["value_min_hex"]), binary64(support["value_max_hex"])
    if index < STATISTICS - 1:
        require(minimum == float(low) and maximum == float(high), "Tick/value mismatch")
    else:
        center = data["pilot"]["center"]
        ends = [(float(t) - center) * (float(t) - center) for t in (low, high)]
        require(maximum == max(ends) and minimum <= min(ends), "Square support mismatch")
        if (
            center <= float(low)
            or center >= float(high)
            or (support["tick_min_count"] + support["tick_max_count"] == support["count"])
        ):
            # Monotonicity, or a certificate with no interior samples, forces
            # both transformed extrema to be attained native endpoints.
            require(minimum == min(ends), "Square support minimum contradicts endpoints")
    if 0 < index < STATISTICS - 1:
        require(high <= data["pilot"]["cutoffs"][index - 1], "Crop includes excluded tick")
    if index:
        require(support["count"] <= raw["count"], "Transformed count exceeds raw")
        require(raw["tick_min"] <= low <= high <= raw["tick_max"], "Support exceeds raw")


def cumulative_support(current: dict[str, Any], previous: dict[str, Any]) -> None:
    require(current["count"] >= previous["count"], "Support count regressed")
    if previous["count"]:
        for endpoint in ("tick_min", "tick_max"):
            if current[endpoint] == previous[endpoint]:
                require(
                    current[endpoint + "_count"] >= previous[endpoint + "_count"],
                    "Endpoint multiplicity regressed",
                )
        require(current["tick_min"] <= previous["tick_min"], "Native minimum increased")
        require(current["tick_max"] >= previous["tick_max"], "Native maximum decreased")
        require(
            binary64(current["value_min_hex"]) <= binary64(previous["value_min_hex"]),
            "Transformed minimum increased",
        )
        require(
            binary64(current["value_max_hex"]) >= binary64(previous["value_max_hex"]),
            "Transformed maximum decreased",
        )


def validate_support(data: dict[str, Any], previous: dict[str, Any] | None = None) -> list[int]:
    supports, statistics = data["support"], data["statistics"]
    require(isinstance(supports, list) and len(supports) == STATISTICS, "Missing native support")
    require(isinstance(statistics, list) and len(statistics) == STATISTICS, "Missing statistics")
    singleton_candidates = []
    for index, (pair, values) in enumerate(zip(supports, statistics, strict=True)):
        require(isinstance(pair, list) and len(pair) == 2, "Missing class support")
        require(isinstance(values, list) and len(values) == 6, "Invalid moments")
        counts = [integer(v) for v in values[:2]]
        for group, support in enumerate(pair):
            class_support(
                support, counts[group], number(values[2 + group]), number(values[4 + group])
            )
            if counts[group]:
                transformed_support(index, support, supports[0][group], data)
            if previous:
                cumulative_support(support, previous["support"][index][group])
            if index == STATISTICS - 1:
                for key in ("count", "tick_min", "tick_max", "tick_min_count", "tick_max_count"):
                    require(
                        support[key] == supports[0][group][key], "Square/native support mismatch"
                    )
            elif index > 1:
                require(
                    counts[group] >= supports[index - 1][group]["count"], "Crop counts regressed"
                )
        ticks = [s[k] for s in pair for k in ("tick_min", "tick_max")]
        if min(counts) > 10000 and len(set(ticks)) == 1 and ticks[0] is not None:
            singleton_candidates.append(index)
    return singleton_candidates


def single_outlier(data: dict[str, Any], index: int) -> tuple[int, int] | None:
    """Exact inclusive absolute-mean permutation tail, selected from pooled ticks.

    Call only after validate_support. Native certificates must also be checked
    against original timing frames before collection completion or admission.
    """
    pair = data["support"][index]
    counts = [s["count"] for s in pair]
    histogram = pooled_endpoints(pair) if min(counts) > 10000 else {}
    if len(histogram) != 2 or sorted(histogram.values()) != [1, sum(counts) - 1]:
        return None
    # Distinct native ticks can alias in binary64 or under centered squaring.
    exact_ticks = all(int(float(value)) == value for value in histogram)
    transformed = [float(value) for value in histogram]
    if index == STATISTICS - 1:
        transformed = [
            (value - data["pilot"]["center"]) * (value - data["pilot"]["center"])
            for value in transformed
        ]
    if (
        not exact_ticks
        or not all(math.isfinite(value) for value in transformed)
        or transformed[0] == transformed[1]
    ):
        return None
    exceptional = next(value for value, count in histogram.items() if count == 1)
    group = next(
        i
        for i, support in enumerate(pair)
        if exceptional in (support["tick_min"], support["tick_max"])
    )
    return single_outlier_tail(counts, group)


def single_outlier_tail(counts: list[int], group: int) -> tuple[int, int]:
    """Inclusive absolute-mean tail, conditional on one exceptional pooled value."""
    return sum(count for count in counts if count <= counts[group]), sum(counts)


def pooled_endpoints(pair: list[dict[str, Any]]) -> dict[int, int]:
    """Empty when native extrema cannot certify the complete pooled multiset."""
    histogram: dict[int, int] = {}
    for support in pair:
        low, high = support["tick_min"], support["tick_max"]
        if low == high:
            histogram[low] = histogram.get(low, 0) + support["count"]
        elif support["tick_min_count"] + support["tick_max_count"] == support["count"]:
            for endpoint in ("tick_min", "tick_max"):
                value = support[endpoint]
                histogram[value] = histogram.get(value, 0) + support[endpoint + "_count"]
        else:
            return {}
    return histogram
