"""Descriptive time-ordered distributions; never used for sample admission."""

from __future__ import annotations

from typing import Any

BLOCKS = 8


def describe(values: list[int]) -> dict[str, Any]:
    values.sort()
    count = len(values)
    return {
        "count": count,
        "order_statistics": (
            dict(
                zip(
                    ("min", "p05", "median", "p95", "max"),
                    (values[i] for i in (0, count // 20, count // 2, 19 * count // 20, count - 1)),
                    strict=True,
                )
            )
            if count
            else None
        ),
    }


def summarize_distribution(deltas: tuple[int, ...], classes: bytes) -> dict[str, Any]:
    # Native update_statistics starts at index 10; the final computation has no
    # following timestamp. Keep negative counts visible, exactly as native does.
    start = min(10, len(deltas))
    size = len(deltas) - start
    whole: list[list[int]] = [[], []]
    blocks = []
    for index in range(BLOCKS):
        lo = start + index * size // BLOCKS
        hi = start + (index + 1) * size // BLOCKS
        groups: list[list[int]] = [[], []]
        negative = 0
        for sample in range(lo, hi):
            value = deltas[sample]
            if value < 0:
                negative += 1
            else:
                groups[classes[sample]].append(value)
        for group in (0, 1):
            whole[group].extend(groups[group])
        blocks.append(
            {
                "indices": [lo, hi],
                "negative_deltas": negative,
                "classes": [describe(values) for values in groups],
            }
        )
    return {
        "indices": [start, len(deltas)],
        "negative_deltas": sum(block["negative_deltas"] for block in blocks),
        "classes": [describe(values) for values in whole],
        "blocks": blocks,
    }


def summarize_context(values: tuple[int, ...], previous_end: int | None) -> dict[str, Any]:
    return {
        "monotonic_ns": list(values[2:4]),
        "duration_ns": values[3] - values[2],
        "gap_before_ns": values[2] - previous_end if previous_end is not None else None,
        "cpus": [None if cpu == 2**64 - 1 else cpu for cpu in values[4:6]],
        "resource_deltas": dict(
            zip(
                (
                    "minor_faults",
                    "major_faults",
                    "voluntary_switches",
                    "involuntary_switches",
                    "user_us",
                    "system_us",
                ),
                (after - before for before, after in zip(values[6::2], values[7::2], strict=True)),
                strict=True,
            )
        ),
    }
