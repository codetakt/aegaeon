# ruff: noqa: PT009, PT027, S603 - explicit Python/native fixture argv without a shell
"""CPU topology, restoration and actual child exec boundary regressions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_affinity import (
    collector_placement,
    cpu_list,
    placement,
    proc_topology,
    validate_placement,
)

ROOT = Path(__file__).resolve().parents[2]


def topology(root, groups):
    for cpu, siblings in groups.items():
        path = root / f"cpu{cpu}/topology/thread_siblings_list"
        path.parent.mkdir(parents=True)
        path.write_text(siblings)
    return root


class DudectAffinityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_sparse_cpuset_excludes_all_native_siblings(self):
        tmp_path = self.root
        plan = placement({2, 7, 19}, topology(tmp_path, {2: "2", 7: "7,19", 19: "7,19"}))
        self.assertEqual(plan["native"], [19])
        self.assertEqual(plan["collector"], [2])
        self.assertEqual(plan["native_siblings"], [7, 19])
        self.assertEqual(plan["original"], [2, 7, 19])

    def test_bad_topology_is_rejected(self):
        for value in ["", "4-2", "1-2-3", "0-4096", "-1", "a"]:
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, r"CPU topology|invalid literal"),
            ):
                cpu_list(value)

    def test_one_core_and_missing_topology_cannot_silently_use_shared_cpu(self):
        tmp_path = self.root
        tree = topology(tmp_path, {2: "2,7", 7: "2,7"})
        with self.assertRaisesRegex(ValueError, "two allowed cores"):
            placement({2, 7}, tree)
        with self.assertRaises(FileNotFoundError):
            placement({2, 8}, tree, tmp_path / "missing-cpuinfo")

    def test_collector_affinity_restored_after_failure(self):
        original = os.sched_getaffinity(0)
        plan = placement(original)
        with self.assertRaisesRegex(RuntimeError, "injected"), collector_placement() as selected:
            self.assertEqual(selected, plan)
            self.assertEqual(os.sched_getaffinity(0), set(plan["collector"]))
            raise RuntimeError("injected")  # noqa: EM101 - explicit failure fixture
        self.assertEqual(os.sched_getaffinity(0), original)

    def test_denied_collector_placement_attempts_restoration(self):
        with (
            patch(
                "dudect_affinity.os.sched_setaffinity", side_effect=[PermissionError, None]
            ) as set_cpu,
            self.assertRaises(PermissionError),
            collector_placement(),
        ):
            self.fail("placement should not yield")
        self.assertEqual(set_cpu.call_count, 2)
        self.assertEqual(set_cpu.call_args.args, (0, os.sched_getaffinity(0)))

    def test_launcher_sets_native_cpu_before_exec_and_preserves_evidence_fd(self):
        tmp_path = self.root
        original = os.sched_getaffinity(0)
        receipt = tmp_path / "affinity.json"
        with collector_placement() as plan, (tmp_path / "native.data").open("wb") as output:
            native = (
                "import os,json; "
                f"os.write({output.fileno()}, b'original evidence'); "
                "print(json.dumps({'pid':os.getpid(),'native':sorted(os.sched_getaffinity(0))}))"
            )
            command = [sys.executable, "-c", native]
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tests/constant_time/dudect_affinity.py"),
                    str(plan["native"][0]),
                    str(receipt),
                    *command,
                ],
                pass_fds=(output.fileno(),),
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            actual = json.loads(result.stdout)
            self.assertEqual(actual["native"], plan["native"])
            self.assertFalse(set(actual["native"]) & os.sched_getaffinity(0))
            self.assertEqual(json.loads(receipt.read_text()), {**actual, "argv": command})
        self.assertEqual(os.sched_getaffinity(0), original)
        self.assertEqual((tmp_path / "native.data").read_bytes(), b"original evidence")

    def test_replay_rejects_missing_or_overlapping_observed_placement(self):
        tmp_path = self.root
        plan = placement({2, 7, 19}, topology(tmp_path, {2: "2", 7: "7,19", 19: "7,19"}))
        process = {"cpu_placement": plan, "argv": ["bound", "pr"]}
        receipt = {"native": [19], "argv": ["bound", "pr"]}
        rows = [{"phase": "observation", "native_affinity": [19], "collector_affinity": [2]}]
        validate_placement(process, receipt, rows)
        with self.assertRaisesRegex(ValueError, "Missing observed"):
            validate_placement(process, receipt, [])
        rows[0]["collector_affinity"] = [7]
        with self.assertRaisesRegex(ValueError, "collector affinity"):
            validate_placement(process, receipt, rows)

    def cpuinfo(self, identities):
        path = self.root / "cpuinfo"
        path.write_text(
            "\n\n".join(
                f"processor\t: {cpu}\nphysical id\t: {package}\ncore id\t: {core}"
                for cpu, package, core in identities
            )
        )
        return path

    def test_nix_missing_sysfs_uses_explicit_proc_package_and_core_ids(self):
        # Core IDs can repeat on different packages. CPU IDs need not be dense.
        info = self.cpuinfo([(2, 0, 0), (7, 1, 0), (19, 1, 0)])
        plan = placement({2, 7, 19}, self.root / "absent-sysfs", info)
        self.assertEqual(plan["native"], [19])
        self.assertEqual(plan["native_siblings"], [7, 19])
        self.assertEqual(plan["collector"], [2])
        self.assertEqual(plan["topology_source"], "proc-package-core-ids")

    def test_proc_requires_complete_unique_topology_for_every_allowed_cpu(self):
        for value in (
            "processor: 0\ncore id: 0",  # package is absent
            "processor: 0\nphysical id: 0\ncore id: -1",
            "processor: 0\nphysical id: 0\ncore id: 0\ncore id: 1",
            "processor: 0\nphysical id: 0\ncore id: 0\n\nprocessor: 0\nphysical id: 0\ncore id: 0",
            "processor: 1\nphysical id: 0\ncore id: 0",  # allowed CPU is absent
        ):
            path = self.root / "cpuinfo"
            path.write_text(value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "topology"):
                proc_topology({0}, path)

    def test_proc_cannot_turn_smt_siblings_into_separate_cores(self):
        info = self.cpuinfo([(0, 0, 0), (1, 0, 0)])
        with self.assertRaisesRegex(ValueError, "two allowed cores"):
            placement({0, 1}, self.root / "absent-sysfs", info)
