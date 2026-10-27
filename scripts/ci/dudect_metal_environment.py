"""Read-back contract for one isolated Ice Lake bare-metal research allocation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dudect_analysis_environment import snapshot as common_snapshot

PROFILE = "dudect-intel-ice-lake-metal/research-1"
EXECUTION = {
    "schema": "dudect-fresh-matrix/research-1",
    "environment": PROFILE,
    "maximum_seconds": 9000,
    "gap_seconds": 10,
    "replacement_trials": 0,
}
SOURCES = [
    "scripts/ci/run_dudect_analysis_matrix.py",
    "scripts/ci/verify_dudect_analysis_matrix.py",
    "scripts/ci/dudect_analysis_environment.py",
    "scripts/ci/dudect_hosted_environment.py",
    "scripts/ci/dudect_metal_environment.py",
]


def cpus(text: str) -> set[int]:
    result: set[int] = set()
    for item in text.split(","):
        parts = [int(v) for v in item.split("-")]
        if len(parts) not in (1, 2) or not 0 <= parts[0] <= parts[-1] < 4096:
            raise ValueError("Invalid CPU set")
        result.update(range(parts[0], parts[-1] + 1))
    return result


def snapshot() -> dict[str, Any]:
    value = common_snapshot()
    value["profile"] = PROFILE
    value["unobservable"] = ["firmware activity", "per-sample event association"]
    value["hardware_attestation"] = "EC2 bare-metal type/instance identity is checked separately"
    base = Path("/sys/devices/system/cpu")
    value["frequency"] = {
        name: (base / name).read_text().strip()
        for name in (
            "intel_pstate/no_turbo",
            "intel_pstate/min_perf_pct",
            "intel_pstate/max_perf_pct",
            "cpufreq/policy1/scaling_driver",
            "cpufreq/policy1/scaling_governor",
            "cpufreq/policy1/scaling_min_freq",
            "cpufreq/policy1/scaling_max_freq",
            "cpufreq/policy1/base_frequency",
        )
    }
    value["native_idle"] = {
        str(p): p.read_text().strip() for p in (base / "cpu1/cpuidle").glob("state*/disable")
    }
    return value


def check(value: dict[str, Any]) -> None:  # noqa: C901, PLR0912, PLR0915 -- explicit profile rejection
    if value["profile"] != PROFILE or value["allowed"] != [0]:
        raise ValueError("Wrong metal profile or supervisor placement")
    online = cpus(value["online"])
    if not {0, 1} <= online or value["smt_active"] != "0":
        raise ValueError("Missing CPUs or active SMT")
    if value["isolated"] != "1" or value["nohz_full"] != "1":
        raise ValueError("Measurement CPU is not isolated")
    options = {
        "nosmt=force",
        "isolcpus=domain,managed_irq,1",
        "nohz_full=1",
        "rcu_nocbs=1",
        "irqaffinity=0",
    }
    if not options <= set(value["cmdline"].split()):
        raise ValueError("Unplanned kernel configuration")
    processors = [p for p in value["cpuinfo"].split("\n\n") if p.strip()]
    for processor in processors:
        fields = dict(line.split(":", 1) for line in processor.splitlines() if ":" in line)
        fields = {k.strip(): v.strip() for k, v in fields.items()}
        flags = set(fields.get("flags", "").split())
        if (
            fields.get("vendor_id") != "GenuineIntel"
            or fields.get("cpu family") != "6"
            or fields.get("model") != "106"
            or "hypervisor" in flags
            or not {"constant_tsc", "nonstop_tsc", "sha_ni"} <= flags
        ):
            raise ValueError("Unexpected CPU model or virtualized execution")
    if len(processors) != len(online):
        raise ValueError("Incomplete CPU inventory")
    topology = value["topology"]
    cores = [(topology[str(i)]["physical_package_id"], topology[str(i)]["core_id"]) for i in (0, 1)]
    if any("" in pair for pair in cores) or cores[0] == cores[1]:
        raise ValueError("Collector and native share a physical core")
    for i in (0, 1):
        if cpus(topology[str(i)]["thread_siblings_list"]) & online != {i}:
            raise ValueError("Online SMT sibling")
    if value["scheduler"] != os.SCHED_OTHER:
        raise ValueError("Unplanned scheduler policy")
    if not value["cpu_quota"] or any(
        v is None or (v != "root_unlimited" and not v.startswith("max "))
        for v in value["cpu_quota"].values()
    ):
        raise ValueError("CPU quota active or unknown")
    if value["user_threads_with_cpu1"] or value["unreadable_processes"]:
        raise ValueError("Additional or unobservable user thread on measurement CPU")
    expected = {
        "intel_pstate/no_turbo": "1",
        "intel_pstate/min_perf_pct": "100",
        "intel_pstate/max_perf_pct": "100",
        "cpufreq/policy1/scaling_driver": "intel_pstate",
        "cpufreq/policy1/scaling_governor": "performance",
    }
    if any(value["frequency"].get(k) != v for k, v in expected.items()):
        raise ValueError("Frequency policy differs from the frozen profile")
    frequencies = [
        value["frequency"]["cpufreq/policy1/" + k]
        for k in ("scaling_min_freq", "scaling_max_freq", "base_frequency")
    ]
    if frequencies != ["2900000"] * 3:
        raise ValueError("Native requested frequency must equal the frozen 2.9 GHz base")
    if not value["native_idle"] or any(v != "1" for v in value["native_idle"].values()):
        raise ValueError("Measurement CPU idle states are not disabled")
