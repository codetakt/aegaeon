"""Reject unqualified hardware/configuration before starting the fixed matrix."""

# ruff: noqa: PT027 -- unittest runs without pytest in standalone checks
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import dudect_metal_environment as metal


def fixture():
    cpu = (
        "vendor_id: GenuineIntel\ncpu family: 6\nmodel: 106\n"
        "flags: constant_tsc nonstop_tsc sha_ni\n"
    )
    freq = {
        "intel_pstate/no_turbo": "1",
        "intel_pstate/min_perf_pct": "100",
        "intel_pstate/max_perf_pct": "100",
        "cpufreq/policy1/scaling_driver": "intel_pstate",
        "cpufreq/policy1/scaling_governor": "performance",
    }
    for k in ("scaling_min_freq", "scaling_max_freq", "base_frequency"):
        freq["cpufreq/policy1/" + k] = "2900000"
    return {
        "profile": metal.PROFILE,
        "allowed": [0],
        "online": "0-3",
        "smt_active": "0",
        "isolated": "1",
        "nohz_full": "1",
        "cpuinfo": "\n".join([cpu] * 4),
        "cmdline": (
            "nosmt=force isolcpus=domain,managed_irq,1 nohz_full=1 rcu_nocbs=1 irqaffinity=0"
        ),
        "topology": {
            str(i): {
                "physical_package_id": "0",
                "core_id": str(i),
                "thread_siblings_list": str(i) + "," + str(i + 4),
            }
            for i in (0, 1)
        },
        "scheduler": 0,
        "cpu_quota": {"root": "root_unlimited", "unit": "max 100000"},
        "user_threads_with_cpu1": [],
        "unreadable_processes": [],
        "frequency": freq,
        "native_idle": {"state0": "1", "state1": "1"},
    }


class MetalTests(unittest.TestCase):
    def test_complete_profile_with_offline_siblings(self):
        metal.check(fixture())

    def test_hardware_configuration_failures(self):
        changes = {
            "profile": "other",
            "allowed": [0, 1],
            "online": "0",
            "smt_active": "1",
            "isolated": "",
            "nohz_full": "",
            "cmdline": "",
            "cpuinfo": "",
            "scheduler": 1,
            "cpu_quota": {"unit": "100000 100000"},
            "user_threads_with_cpu1": [42],
            "unreadable_processes": [42],
            "native_idle": {},
        }
        for key, bad in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                data = fixture()
                data[key] = bad
                metal.check(data)
        for key in fixture()["frequency"]:
            with self.subTest(frequency=key), self.assertRaises(ValueError):
                data = fixture()
                data["frequency"][key] = "unknown"
                metal.check(data)

    def test_virtual_cpu_wrong_model_and_shared_core(self):
        for old, new in [("sha_ni", "sha_ni hypervisor"), ("model: 106", "model: 143")]:
            with self.subTest(new=new), self.assertRaises(ValueError):
                data = fixture()
                data["cpuinfo"] = data["cpuinfo"].replace(old, new)
                metal.check(data)
        data = fixture()
        data["topology"]["1"]["core_id"] = "0"
        with self.assertRaises(ValueError):
            metal.check(data)
        data = fixture()
        data["topology"]["1"]["thread_siblings_list"] = "1,2"
        with self.assertRaises(ValueError):
            metal.check(data)

    def test_invalid_cpu_ranges(self):
        for text in ("", "2-1", "-1", "0-2-3", "4096"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                metal.cpus(text)
