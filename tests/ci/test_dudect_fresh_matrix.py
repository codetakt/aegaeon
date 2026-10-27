"""Fresh ownership, complete coverage and separate environment/statistical outcomes."""

# ruff: noqa: PT009, PT027
from __future__ import annotations

import contextlib
import copy
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import dudect_analysis_environment as environment
import dudect_metal_environment as metal
import run_dudect_analysis_matrix as fresh
import test_dudect_analysis_matrix as fixtures
import test_dudect_metal as metal_fixture
import verify_dudect_analysis_matrix as verifier


def good_environment():
    return {
        "profile": environment.PROFILE,
        "online": "0-1",
        "isolated": "1",
        "nohz_full": "1",
        "smt_active": "0",
        "allowed": [0],
        "cpuinfo": "AuthenticAMD AMD EPYC 7R13",
        "cmdline": (
            "nosmt=force isolcpus=domain,managed_irq,1 nohz_full=1 rcu_nocbs=1 irqaffinity=0"
        ),
        "topology": {
            str(i): {"physical_package_id": "0", "core_id": str(i), "thread_siblings_list": str(i)}
            for i in (0, 1)
        },
        "scheduler": os.SCHED_OTHER,
        "cpu_quota": {"root": "root_unlimited", "current": "max 100000"},
        "user_threads_with_cpu1": [],
        "unreadable_processes": [],
        "events": {"switches": 17, "faults": 8},
    }


class EnvironmentTests(unittest.TestCase):
    def test_nonzero_events_not_an_automatic_failure(self):
        environment.check(good_environment())

    def test_configuration_or_visibility_failure(self):
        for key, value in (
            ("online", "0-3"),
            ("isolated", ""),
            ("smt_active", "1"),
            ("allowed", [0, 1]),
            ("cpuinfo", "Intel"),
            ("cmdline", ""),
            ("scheduler", os.SCHED_FIFO),
            ("user_threads_with_cpu1", [42]),
            ("unreadable_processes", [42]),
            ("cpu_quota", {"current": None}),
            ("cpu_quota", {"current": "10000 100000"}),
        ):
            with self.subTest(key=key, value=value):
                state = good_environment()
                state[key] = value
                with self.assertRaises(ValueError):
                    environment.check(state)

    def test_same_core_and_sibling_rejected(self):
        state = good_environment()
        state["topology"]["1"]["core_id"] = "0"
        with self.assertRaises(ValueError):
            environment.check(state)


class FreshTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.MatrixTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.plan = copy.deepcopy(fixture.plan)
        self.plan["execution"] = copy.deepcopy(fresh.EXECUTION)
        self.out = fixture.root / "fresh"
        self.out.mkdir()
        self.enterContext(patch.object(verifier, "store_path", side_effect=Path))
        self.enterContext(patch.object(fresh.os, "sched_setaffinity"))
        self.enterContext(patch.object(fresh, "snapshot", side_effect=good_environment))
        self.enterContext(patch.object(fresh.time, "sleep"))
        self.real_popen = subprocess.Popen
        self.spawn = self.enterContext(
            patch.object(fresh.subprocess, "Popen", side_effect=self.capture)
        )

    def capture(self, argv, **_kwargs):
        unit = argv[argv.index("--unit") + 1]
        output = Path(argv[argv.index("--output") + 1])
        self.assertIn("--launch", argv)
        self.assertNotIn("--verify-only", argv)
        output.mkdir()
        shutil.copyfile(
            self.fixture.evidence / unit / "gate/research-report.json",
            output / "research-report.json",
        )
        report = json.loads((output / "research-report.json").read_text())
        return SimpleNamespace(wait=lambda **_: 0 if report["gate_satisfied"] else 1)

    def metal_plan(self):
        self.plan["execution"] = copy.deepcopy(metal.EXECUTION)
        root = Path(__file__).resolve().parents[2]
        self.plan["orchestration"] = {name: fresh.sha256(root / name) for name in metal.SOURCES}
        self.enterContext(patch.object(metal, "snapshot", side_effect=metal_fixture.fixture))

    def test_metal_complete_path_and_environment_receipts(self):
        self.metal_plan()
        result = fresh.run(self.plan, self.out)
        self.assertTrue(result["complete"])
        self.assertFalse(result["ci_admission"])
        self.assertEqual(self.spawn.call_count, 4)
        for unit in self.plan["units"]:
            for when in ("before", "after"):
                value = json.loads((self.out / unit["id"] / f"environment-{when}.json").read_text())
                self.assertEqual(value["profile"], fresh.metal.PROFILE)

    def test_metal_changed_or_incomplete_binding_cannot_start(self):
        self.metal_plan()
        key = next(iter(self.plan["orchestration"]))
        self.plan["orchestration"][key] = "0" * 64
        with self.assertRaisesRegex(ValueError, "orchestration changed"):
            fresh.run(self.plan, self.out)
        self.spawn.assert_not_called()
        del self.plan["orchestration"][key]
        with self.assertRaisesRegex(ValueError, "Incomplete metal"):
            fresh.run(self.plan, self.out)
        self.spawn.assert_not_called()

    def test_all_four_units_fresh_once(self):
        result = fresh.run(self.plan, self.out)
        self.assertTrue(result["complete"])
        self.assertTrue(result["research_requirements_satisfied"])
        self.assertFalse(result["ci_admission"])
        self.assertEqual(self.spawn.call_count, 4)
        self.assertEqual(sum(len(r["assessment"]) for r in result["units"]), 42)

    def test_cli_relative_output_survives_collector_working_directory(self):
        # Exercise the nested cwd/launcher boundary that an absolute-only fixture
        # misses. No timing is performed by this child.
        def launch_from_snapshot(argv, **kwargs):
            output = Path(argv[argv.index("--output") + 1])
            snapshot = output / "package/sources"
            snapshot.mkdir(parents=True)
            helper = snapshot / "helper.py"
            helper.write_text(
                "import pathlib, sys\npathlib.Path(sys.argv[1]).write_text('launched')\n"
            )
            receipt = output / "launched.txt"
            child = self.real_popen(
                [sys.executable, str(helper), str(receipt)],
                cwd=snapshot,
                stdout=kwargs["stdout"],
                stderr=kwargs["stderr"],
            )
            code = child.wait(timeout=10)
            if code == 0:
                self.assertEqual(receipt.read_text(), "launched")
                unit = argv[argv.index("--unit") + 1]
                shutil.copyfile(
                    self.fixture.evidence / unit / "gate/research-report.json",
                    output / "research-report.json",
                )
            return SimpleNamespace(wait=lambda **_: code)

        self.spawn.side_effect = launch_from_snapshot
        plan = self.fixture.root / "plan.json"
        fixtures.write(plan, self.plan)
        with (
            contextlib.chdir(self.fixture.root),
            patch.object(
                sys,
                "argv",
                [
                    "fresh",
                    "--plan",
                    "plan.json",
                    "--plan-sha256",
                    fresh.sha256(plan),
                    "--output",
                    "relative-output",
                ],
            ),
        ):
            self.assertEqual(fresh.main(), 0)
        self.assertEqual(self.spawn.call_count, 4)
        result = json.loads((self.fixture.root / "relative-output/summary.json").read_text())
        self.assertTrue(result["complete"])

    def test_statistical_failure_does_not_skip_later_units(self):
        self.fixture.change_report(
            lambda r: (
                r.update(gate_satisfied=False),
                r["assessment"][0].update(requirement_satisfied=False),
            )
        )
        result = fresh.run(self.plan, self.out)
        self.assertTrue(result["complete"])
        self.assertFalse(result["research_requirements_satisfied"])
        self.assertEqual(self.spawn.call_count, 4)

    def test_post_environment_failure_preserves_statistics(self):
        with (
            patch.object(fresh, "environment", side_effect=[None, ValueError("moved")]),
            self.assertRaises(ValueError),
        ):
            fresh.run(self.plan, self.out)
        value = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(len(value["units"]), 1)
        self.assertTrue(value["units"][0]["requirement_satisfied"])
        self.assertFalse(value["units"][0]["environment_satisfied"])
        self.assertEqual(len(value["unstarted"]), 3)

    def test_invalid_environment_saved_before_launch(self):
        state = good_environment()
        state["smt_active"] = "1"
        with patch.object(fresh, "snapshot", return_value=state), self.assertRaises(ValueError):
            fresh.run(self.plan, self.out)
        self.spawn.assert_not_called()
        self.assertTrue(
            (self.out / self.plan["units"][0]["id"] / "environment-before.json").exists()
        )

    def test_missing_cell_rejected_before_launch(self):
        self.plan["units"].pop()
        with self.assertRaises(ValueError):
            fresh.run(self.plan, self.out)
        self.spawn.assert_not_called()

    def test_timeout_stops_child_and_records_unstarted(self):
        child = SimpleNamespace(
            pid=42,
            wait=lambda **_: (_ for _ in ()).throw(subprocess.TimeoutExpired("child", 1)),
            poll=lambda: None,
        )
        # The first wait times out, cleanup then succeeds.
        with (
            patch.object(child, "wait", side_effect=[subprocess.TimeoutExpired("child", 1), 0, 0]),
            patch.object(fresh.os, "killpg") as kill,
        ):
            self.spawn.side_effect = lambda *a, **k: child
            with self.assertRaises(subprocess.TimeoutExpired):
                fresh.run(self.plan, self.out)
            kill.assert_called_once_with(42, 15)
        value = json.loads((self.out / "summary.json").read_text())
        self.assertFalse(value["complete"])
        self.assertEqual(len(value["unstarted"]), 3)


if __name__ == "__main__":
    unittest.main()
