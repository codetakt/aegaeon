"""Separate the collector from the native core without claiming host isolation."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from dudect_results import invalid
from dudect_support import require

if TYPE_CHECKING:
    from collections.abc import Iterator


def cpu_list(value: str) -> set[int]:
    cpus: set[int] = set()
    for item in value.strip().split(","):
        bounds = item.split("-")
        require(len(bounds) in (1, 2), "Invalid CPU topology range")
        low, high = int(bounds[0]), int(bounds[-1])
        require(0 <= low <= high < 4096, "Unbounded CPU topology range")
        cpus.update(range(low, high + 1))
    return cpus


def placement(
    allowed: set[int], topology: Path = Path("/sys/devices/system/cpu")
) -> dict[str, Any]:
    require(bool(allowed) and len(allowed) <= 4096, "Invalid allowed CPU set")
    # The highest eligible CPU avoids assuming CPU IDs are dense or start at 0.
    for cpu in sorted(allowed, reverse=True):
        siblings = cpu_list((topology / f"cpu{cpu}/topology/thread_siblings_list").read_text())
        require(cpu in siblings, "CPU missing from its sibling topology")
        collector = allowed - siblings
        if collector:
            return {
                "mode": "separate-core",
                "original": sorted(allowed),
                "native": [cpu],
                "native_siblings": sorted(siblings),
                "collector": sorted(collector),
                "scope": "owned processes only; no IRQ, host or exclusive CPU guarantee",
            }
    return invalid("Dudect needs two allowed cores to separate measurement and collection")


@contextlib.contextmanager
def collector_placement() -> Iterator[dict[str, Any]]:
    require(hasattr(os, "sched_setaffinity"), "Dudect CPU separation requires Linux affinity")
    original = os.sched_getaffinity(0)
    plan = placement(original)
    try:
        os.sched_setaffinity(0, plan["collector"])
        require(os.sched_getaffinity(0) == set(plan["collector"]), "Collector affinity mismatch")
        yield plan
    finally:
        os.sched_setaffinity(0, original)
        require(os.sched_getaffinity(0) == original, "Collector affinity restoration failed")


def launch() -> None:
    """Set affinity before exec, retaining PID, process group and evidence FDs."""
    cpu, receipt, *command = sys.argv[1:]
    require(bool(command), "Missing native command")
    os.sched_setaffinity(0, {int(cpu)})
    actual = sorted(os.sched_getaffinity(0))
    require(actual == [int(cpu)], "Native affinity mismatch")
    with Path(receipt).open("x") as output:
        json.dump({"pid": os.getpid(), "native": actual, "argv": command}, output)
    os.execv(command[0], command)  # noqa: S606 - exact bound native executable, no shell


def validate_placement(
    process: dict[str, Any], receipt: dict[str, Any], rows: list[dict[str, Any]]
) -> None:
    plan = process.get("cpu_placement")
    require(isinstance(plan, dict) and plan.get("mode") == "separate-core", "Missing CPU placement")
    plan = cast("dict[str, Any]", plan)
    groups = {}
    for name in ("original", "native", "native_siblings", "collector"):
        value = plan.get(name)
        require(
            isinstance(value, list)
            and bool(value)
            and all(type(cpu) is int and 0 <= cpu < 4096 for cpu in value),
            "Invalid recorded CPU set",
        )
        value = cast("list[int]", value)
        require(value == sorted(set(value)), "Unordered recorded CPU set")
        groups[name] = set(value)
    require(
        len(groups["native"]) == 1
        and groups["native"] <= groups["original"] & groups["native_siblings"]
        and groups["collector"] == groups["original"] - groups["native_siblings"],
        "Native and collector cores are not separated",
    )
    require(
        receipt.get("native") == plan["native"] and receipt.get("argv") == process["argv"],
        "Native affinity receipt mismatch",
    )
    observations = [row for row in rows if row.get("phase") == "observation"]
    require(bool(observations), "Missing observed CPU placement")
    require(
        all(row.get("collector_affinity") == plan["collector"] for row in rows),
        "Observed collector affinity mismatch",
    )
    require(
        all(row.get("native_affinity") == plan["native"] for row in observations),
        "Observed native affinity mismatch",
    )


if __name__ == "__main__":
    launch()
