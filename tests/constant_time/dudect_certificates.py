"""Bounded raw-frame verification of every single-outlier inference certificate."""

from __future__ import annotations

import bisect
import itertools
import struct
from collections import Counter
from typing import Any

from dudect_results import STATISTICS
from dudect_support import require, single_outlier, validate_support

KEYS = ("count", "tick_min", "tick_max", "tick_min_count", "tick_max_count")


def cutoff(row: dict[str, Any], index: int) -> int | None:
    return row["pilot"]["cutoffs"][index - 1] if 0 < index < STATISTICS - 1 else None


class Certificates:
    """Keep at most 101 cumulative endpoint summaries, never all native samples.

    The existing framing validator reads all frames, even when no new inference
    is used. Only the new single-outlier method relies on this additional check.
    """

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.targets: dict[int, list[tuple[dict[str, Any], int]]] = {}
        self.summaries: dict[int | None, list[dict[str, Any]]] = {}
        for row in rows:
            validate_support(row)
            targets = [
                (row, index)
                for index in range(STATISTICS)
                if single_outlier(row, index) is not None
            ]
            if targets:
                require(row["batches"] not in self.targets, "Duplicate certificate look")
                self.targets[row["batches"]] = targets
            for observation, index in targets:
                self.summaries[cutoff(observation, index)] = [
                    dict(zip(KEYS, (0, None, None, 0, 0), strict=True)) for _ in (0, 1)
                ]
        self.checked = 0

    def push(self, payload: bytes, batch: int, size: int) -> None:
        if batch == 0 or not self.summaries:
            return
        ticks = struct.unpack_from(f"<{size}q", payload)
        classes = payload[size * 8 : size * 9]
        histograms: list[Counter[int]] = [Counter(), Counter()]
        for sample in range(10, size - 1):
            value = ticks[sample + 1] - ticks[sample]
            if value >= 0:
                histograms[classes[sample]][value] += 1
        self.accumulate(histograms)
        for row, index in self.targets.pop(batch, []):
            for actual, expected in zip(
                self.summaries[cutoff(row, index)], row["support"][index], strict=True
            ):
                require(
                    actual == {key: expected[key] for key in KEYS},
                    "Single-outlier certificate differs from original timing samples",
                )
            self.checked += 1

    def finish(self) -> int:
        require(not self.targets, "Missing single-outlier certificate frames")
        return self.checked

    def accumulate(self, histograms: list[Counter[int]]) -> None:
        for group, histogram in enumerate(histograms):
            values = sorted(histogram)
            totals = list(itertools.accumulate(histogram[value] for value in values))
            for limit, summaries in self.summaries.items():
                end = len(values) if limit is None else bisect.bisect_right(values, limit)
                if not end:
                    continue
                summary = summaries[group]
                for endpoint, value in (("tick_min", values[0]), ("tick_max", values[end - 1])):
                    previous = summary[endpoint]
                    if previous is None or (
                        value < previous if endpoint == "tick_min" else value > previous
                    ):
                        summary[endpoint] = value
                        summary[endpoint + "_count"] = histogram[value]
                    elif previous == value:
                        summary[endpoint + "_count"] += histogram[value]
                summary["count"] += totals[end - 1]
