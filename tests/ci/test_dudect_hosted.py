"""Hosted placement, bounded ownership and partial-evidence retention."""

# ruff: noqa: PT009, PT027, E402, S603 -- unittest fixtures and fixed local child argv
from __future__ import annotations

import copy
import json
import os
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import dudect_hosted_environment as hosted
import retain_dudect_hosted as retention
import run_dudect_analysis_matrix as fresh
import test_dudect_fresh_matrix as fixtures
from verify_dudect_analysis_matrix import sha256


def config():
    return {
        "runner": dict(
            zip(
                hosted.RUNNER_FIELDS,
                [
                    "true",
                    "github-hosted",
                    "Linux",
                    "X64",
                    "ubuntu24",
                    "20261016",
                    "123",
                    "1",
                    "a" * 40,
                ],
                strict=True,
            )
        ),
        "placement": {
            "original": [2, 4, 6, 8],
            "native": [8],
            "native_siblings": [6, 8],
            "collector": [2, 4],
            "mode": "separate-core",
            "topology_source": "sysfs-thread-siblings",
            "scope": "fixture",
        },
    }


def observed():
    value = config()
    return {
        **copy.deepcopy(value),
        "profile": hosted.PROFILE,
        "machine": "x86_64",
        "supervisor_affinity": [2, 4],
        "scheduler": os.SCHED_OTHER,
        "cgroup": {"limits": {"root": "root_unlimited", "child": "max 100000"}},
        "competition_exclusion_established": False,
        "competing_user_threads": [{"pid": 500}],
        "unreadable_processes": [501],
        "events": {"switches": 17},
    }


class HostedEnvironmentTests(unittest.TestCase):
    def test_observed_competition_is_not_hidden_or_claimed_excluded(self):
        hosted.check(observed(), config())

    def test_required_configuration_failures(self):
        for key, value in (
            ("supervisor_affinity", [2, 8]),
            ("scheduler", os.SCHED_FIFO),
            ("competition_exclusion_established", True),
            ("machine", "aarch64"),
            ("cgroup", {"limits": {"child": "10000 100000"}}),
            ("cgroup", {"limits": {"child": {"unavailable": "PermissionError"}}}),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                hosted.check({**observed(), key: value}, config())

    def test_wrong_runner_and_replacement_attempt_rejected(self):
        for key, value in (
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("ImageVersion", ""),
        ):
            state = observed()
            state["runner"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                hosted.check(state, config())

    def test_quota_all_ancestors_and_unknown_nonroot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a/b").mkdir(parents=True)
            (root / "a/cpu.max").write_text("50000 100000")
            (root / "a/b/cpu.max").write_text("max 100000")
            result = hosted.quota(root, "0::/a/b")
            self.assertEqual(len(result["limits"]), 3)
            self.assertEqual(result["limits"][str(root / "a/cpu.max")], "50000 100000")
            self.assertEqual(result["limits"][str(root / "cpu.max")], "root_unlimited")
            (root / "a/cpu.max").unlink()
            self.assertIn(
                "unavailable", hosted.quota(root, "0::/a/b")["limits"][str(root / "a/cpu.max")]
            )
            with self.assertRaises(ValueError):
                hosted.quota(root, "0::/../../host")
            (root / "cgroup.subtree_control").write_text("memory")
            self.assertEqual(
                hosted.quota(root, "0::/a/b")["limits"][str(root / "a/cpu.max")],
                "controller_disabled_by_parent",
            )
            with self.assertRaises(ValueError):
                hosted.quota(root, "0::/a/b\n2:cpu,cpuacct:/restricted")

    def test_dynamic_sibling_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for cpu, siblings in ((2, "2,4"), (4, "2,4"), (6, "6,8"), (8, "6,8")):
                path = root / f"cpu{cpu}/topology/thread_siblings_list"
                path.parent.mkdir(parents=True)
                path.write_text(siblings)
            selected = hosted.placement({2, 4, 6, 8}, root)
            self.assertEqual(selected["native"], [8])
            self.assertEqual(selected["collector"], [2, 4])
            with self.assertRaises(ValueError):
                hosted.placement({6, 8}, root)


class HostedExecutionTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.FreshTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.plan = fixture.plan
        self.plan["execution"] = copy.deepcopy(hosted.EXECUTION)
        self.plan["hosted"] = config()
        self.plan["units"].sort(key=lambda u: hosted.ORDER.index((u["compiler"], u["suite"])))
        self.plan["orchestration"] = {name: sha256(ROOT / name) for name in hosted.SOURCES}
        self.enterContext(patch.object(hosted, "placement", return_value=config()["placement"]))
        self.enterContext(patch.object(fresh.os, "sched_getaffinity", return_value={2, 4, 6, 8}))
        self.enterContext(patch.object(hosted, "snapshot", side_effect=lambda _: observed()))

    def test_hosted_full_matrix_no_adoption_or_exclusion_claim(self):
        value = fresh.run(self.plan, self.fixture.out)
        self.assertTrue(value["complete"])
        self.assertFalse(value["ci_admission"])
        self.assertFalse(value["competition_exclusion_established"])
        for call in self.fixture.spawn.call_args_list:
            argv = call.args[0]
            self.assertEqual(argv[argv.index("--launch-cpus") + 1], "2,4,6,8")
        self.assertEqual(self.fixture.spawn.call_count, 4)

    def test_wrong_order_or_missing_orchestration_rejected(self):
        for change in (lambda p: p["units"].reverse(), lambda p: p["orchestration"].popitem()):
            plan = copy.deepcopy(self.plan)
            change(plan)
            with self.assertRaises(ValueError):
                fresh.run(plan, self.fixture.out)
        self.fixture.spawn.assert_not_called()

    def test_cancel_preserves_partial_and_unstarted(self):
        class Child:
            pid = 42

            def poll(self):
                return None

        child = Child()
        with (
            patch.object(
                child, "wait", create=True, side_effect=[InterruptedError("cancelled"), 0, 0]
            ),
            patch.object(fresh.os, "killpg") as kill,
        ):
            self.fixture.spawn.side_effect = lambda *a, **k: child
            with self.assertRaises(InterruptedError):
                fresh.run(self.plan, self.fixture.out)
            kill.assert_called_once_with(42, signal.SIGTERM)
        result = json.loads((self.fixture.out / "summary.json").read_text())
        self.assertFalse(result["complete"])
        self.assertEqual(len(result["unstarted"]), 3)


class RetentionTests(unittest.TestCase):
    def test_failed_partial_raw_is_archived_and_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "native.timing").write_bytes(b"partial frame\x00\xff")
            (source / "execution-failure.json").write_text('{"error":"deadline"}')
            value = retention.retain(source, root / "archive")
            self.assertEqual(len(value["files"]), 2)
            with tarfile.open(root / "archive/evidence.tar.gz") as archive:
                self.assertEqual(
                    archive.extractfile("evidence/native.timing").read(), b"partial frame\x00\xff"
                )

    def test_never_follow_symlink_to_private_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "source").mkdir()
            (root / "private").write_text("private")
            (root / "source/link").symlink_to(root / "private")
            with self.assertRaises(ValueError):
                retention.retain(root / "source", root / "archive")

    def test_actual_launch_reserves_requested_dynamic_cpus(self):
        allowed = sorted(os.sched_getaffinity(0))
        selected = allowed[:1]
        command = [
            sys.executable,
            "-B",
            str(ROOT / "scripts/ci/run_dudect_analysis_matrix.py"),
            "--launch-cpus",
            str(selected[0]),
            "--launch",
            sys.executable,
            "-c",
            "import os,json; print(json.dumps(sorted(os.sched_getaffinity(0))))",
        ]
        result = subprocess.check_output(command, text=True, timeout=10)
        self.assertEqual(json.loads(result), selected)


if __name__ == "__main__":
    unittest.main()
