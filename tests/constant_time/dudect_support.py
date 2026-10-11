"""Strict native support validation for the inactive observation candidate."""

from __future__ import annotations

import math
import re
from typing import Any

from dudect_results import STATISTICS, integer, invalid, number


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


def class_support(support: Any, count: int, mean: float, m2: float) -> None:
    keys = {"count", "tick_min", "tick_max", "value_min_hex", "value_max_hex"}
    require(isinstance(support, dict) and set(support) == keys, "Invalid native support")
    require(integer(support["count"]) == count, "Support count mismatch")
    if not count:
        require(all(support[k] is None for k in keys - {"count"}), "Empty support has extrema")
        require(mean == 0 and m2 == 0, "Empty class has moments")
        return
    low, high = tick(support["tick_min"]), tick(support["tick_max"])
    minimum, maximum = binary64(support["value_min_hex"]), binary64(support["value_max_hex"])
    require(low <= high and minimum <= maximum, "Reversed support")
    require(minimum <= mean <= maximum, "Mean outside native support")
    if minimum == maximum:
        require(mean == minimum and m2 == 0, "Singleton support contradicts moments")
    else:
        require(m2 > 0 and count >= 2, "Distinct support contradicts moments")


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
    if 0 < index < STATISTICS - 1:
        require(high <= data["pilot"]["cutoffs"][index - 1], "Crop includes excluded tick")
    if index:
        require(support["count"] <= raw["count"], "Transformed count exceeds raw")
        require(raw["tick_min"] <= low <= high <= raw["tick_max"], "Support exceeds raw")


def cumulative_support(current: dict[str, Any], previous: dict[str, Any]) -> None:
    require(current["count"] >= previous["count"], "Support count regressed")
    if previous["count"]:
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
                for key in ("count", "tick_min", "tick_max"):
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
