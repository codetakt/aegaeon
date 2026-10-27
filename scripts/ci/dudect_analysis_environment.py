"""Required guest configuration, observed events and unknown host conditions."""

from __future__ import annotations

import datetime
import os
import platform
from pathlib import Path
from typing import Any

PROFILE = "dudect-amd-epyc7r13-isolated-guest/research-1"


def verify(snapshot: dict[str, Any]) -> None:  # noqa: C901, PLR0912 -- explicit required configuration
    if snapshot["online"] != "0-1" and snapshot["online"] != "0,1":
        raise ValueError("Expected exactly CPUs 0 and 1 online")
    if snapshot["isolated"] != "1" or snapshot["nohz_full"] != "1":
        raise ValueError("CPU1 isolation/nohz not present")
    if snapshot["smt_active"] != "0":
        raise ValueError("SMT is active")
    if snapshot["allowed"] != [0]:
        raise ValueError("Campaign supervisor must be pinned to CPU0")
    if "AuthenticAMD" not in snapshot["cpuinfo"] or "AMD EPYC 7R13" not in snapshot["cpuinfo"]:
        raise ValueError("Expected AMD processor")
    topology = snapshot["topology"]
    cores = [(topology[str(i)]["physical_package_id"], topology[str(i)]["core_id"]) for i in (0, 1)]
    if any("" in pair for pair in cores) or cores[0] == cores[1]:
        raise ValueError("CPUs 0 and 1 must map to distinct guest physical cores")
    for i in (0, 1):
        if topology[str(i)]["thread_siblings_list"] != str(i):
            raise ValueError("Unexpected SMT sibling topology")
    for option in (
        "nosmt=force",
        "isolcpus=domain,managed_irq,1",
        "nohz_full=1",
        "rcu_nocbs=1",
        "irqaffinity=0",
    ):
        if option not in snapshot["cmdline"].split():
            raise ValueError("Missing frozen kernel option: " + option)


def snapshot() -> dict[str, Any]:  # noqa: C901, PLR0912, PLR0915 -- preserve complete environment receipt
    base = Path("/sys/devices/system/cpu")
    value: dict[str, Any] = {
        name: (base / path).read_text().strip()
        for name, path in [
            ("online", "online"),
            ("isolated", "isolated"),
            ("nohz_full", "nohz_full"),
            ("smt_active", "smt/active"),
        ]
    }
    value.update(
        profile=PROFILE,
        cpuinfo=Path("/proc/cpuinfo").read_text(),
        cmdline=Path("/proc/cmdline").read_text().strip(),
        allowed=sorted(os.sched_getaffinity(0)),
        kernel=platform.release(),
        checked_at=datetime.datetime.now(datetime.UTC).isoformat(),
        scheduler=os.sched_getscheduler(0),
    )
    value["topology"] = {
        str(i): {
            name: (base / f"cpu{i}/topology" / name).read_text().strip()
            for name in ("physical_package_id", "core_id", "thread_siblings_list")
        }
        for i in (0, 1)
    }
    value["events"] = {
        name: Path("/proc", name).read_text() for name in ("stat", "interrupts", "softirqs")
    }
    value["irq_affinity"] = {}
    for file in Path("/proc/irq").glob("*/smp_affinity_list"):
        try:
            value["irq_affinity"][str(file)] = file.read_text().strip()
        except OSError as error:
            value["irq_affinity"][str(file)] = {"unavailable": type(error).__name__}
    value["cgroup"] = Path("/proc/self/cgroup").read_text()
    group = next(
        line.split(":", 2)[2] for line in value["cgroup"].splitlines() if line.startswith("0::")
    )
    directory = Path("/sys/fs/cgroup") / group.lstrip("/")
    value["cpu_quota"] = {}
    for ancestor in (directory, *directory.parents):
        if ancestor == Path("/sys/fs/cgroup").parent:
            break
        file = ancestor / "cpu.max"
        value["cpu_quota"][str(file)] = (
            file.read_text().strip()
            if file.exists()
            else ("root_unlimited" if ancestor == Path("/sys/fs/cgroup") else None)
        )
    value["cpu_throttling"] = (directory / "cpu.stat").read_text()
    value["user_threads_with_cpu1"] = []
    value["unreadable_processes"] = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            # Kernel threads have no executable; this checks known user threads.
            executable = process.joinpath("exe").readlink()
            for thread in process.joinpath("task").iterdir():
                affinity = sorted(os.sched_getaffinity(int(thread.name)))
                if 1 in affinity:
                    value["user_threads_with_cpu1"].append(
                        {
                            "pid": int(process.name),
                            "tid": int(thread.name),
                            "exe": str(executable),
                            "affinity": affinity,
                        }
                    )
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            value["unreadable_processes"].append(int(process.name))
    value["unobservable"] = [
        "physical core exclusivity",
        "hypervisor pauses",
        "firmware activity",
        "per-sample event association",
    ]
    value["interpretation"] = "Events are retained, not zero-count gates or sample filters."
    return value


def check(value: dict[str, Any]) -> None:
    verify(value)
    if value["profile"] != PROFILE or value["scheduler"] != os.SCHED_OTHER:
        raise ValueError("Unplanned environment profile or scheduler")
    if not value["cpu_quota"] or any(
        v is None or (v != "root_unlimited" and not v.startswith("max "))
        for v in value["cpu_quota"].values()
    ):
        raise ValueError("CPU quota active or unknown")
    if value["user_threads_with_cpu1"] or value["unreadable_processes"]:
        raise ValueError("Additional or unobservable user thread affinity")
