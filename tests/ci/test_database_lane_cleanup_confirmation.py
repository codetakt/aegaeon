"""Keep dependencies available until every started process owner confirms cleanup."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions survive Python -O.
import contextlib
import json
import os
import signal
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts/ci"), str(ROOT / "scripts/validation")]
import database_execution as execution  # noqa: E402
import run_database_lanes as lanes  # noqa: E402


class DatabaseLaneCleanupConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.plan_path = self.directory / "plan.json"
        self.plan_path.write_text('{"fixture":"cleanup-confirmation"}\n')
        self.plan = {
            "package": str(self.directory / "package"),
            "context": {"GITHUB_RUN_ID": "fixture", "GITHUB_RUN_ATTEMPT": "1"},
            "build_sha256": "fixture-build",
        }
        self.results = self.directory / "results"
        self.results.mkdir()
        # Package discovery and native execution have separate existing tests.
        # These fixtures exercise the real cleanup consumer and its receipt bytes.
        self.enterContext(mock.patch.object(execution, "load_plan", return_value=self.plan))
        self.enterContext(mock.patch.object(lanes, "load_plan", return_value=self.plan))

    def receipt(self, filename, **changes):
        row = {
            "name": filename,
            "context": self.plan["context"],
            "plan_sha256": execution.sha(self.plan_path),
            "build_sha256": self.plan["build_sha256"],
            "process_cleanup_confirmed": True,
            # Failed tests can safely release dependencies after confirmed stop.
            "complete": False,
            "returncode": 37,
        }
        row.update(changes)
        (self.results / f"{filename}.json").write_text(json.dumps(row))
        return row

    def confirm(self, lane="postgres", *, require_all=False):
        execution.confirm_lane_cleanup(self.plan_path, self.results, lane, require_all=require_all)

    def test_absent_future_receipts_require_outer_stop_boundary(self):
        self.confirm()
        with pytest.raises(ValueError, match="no cleanup receipt"):
            self.confirm(require_all=True)
        self.receipt("fixture-guards")
        self.confirm()
        with pytest.raises(ValueError, match="pre-migration"):
            self.confirm(require_all=True)

    def test_failed_but_stopped_owners_allow_strict_cleanup(self):
        for name in ("fixture-guards", "pre-migration", "postgres", "dcr"):
            self.receipt(name)
        self.confirm(require_all=True)

    def test_every_lane_obligation_and_all_scope_are_checked(self):
        expected = {
            "redis": ("redis",),
            "postgres": ("fixture-guards", "pre-migration", "postgres", "dcr"),
            "mixed": ("mixed",),
        }
        for names in expected.values():
            for name in names:
                self.receipt(name)
        self.confirm("all", require_all=True)
        for lane, names in expected.items():
            for name in names:
                with self.subTest(lane=lane, name=name):
                    self.receipt(name, process_cleanup_confirmed=False)
                    with pytest.raises(ValueError, match=name):
                        self.confirm(lane)
                    with pytest.raises(ValueError, match=name):
                        self.confirm("all")
                    for other in expected:
                        if other != lane:
                            self.confirm(other, require_all=True)
                    self.receipt(name)

    def test_success_without_explicit_stop_confirmation_is_rejected(self):
        path = self.results / "postgres.json"
        for value in (False, None, 1, "true"):
            with self.subTest(value=value):
                self.receipt(
                    "postgres", complete=True, returncode=0, process_cleanup_confirmed=value
                )
                with pytest.raises(ValueError, match="cleanup is unconfirmed"):
                    self.confirm()
        row = self.receipt("postgres", complete=True, returncode=0)
        del row["process_cleanup_confirmed"]
        path.write_text(json.dumps(row))
        with pytest.raises(ValueError, match="cleanup is unconfirmed"):
            self.confirm()

    def test_foreign_receipt_binding_is_rejected(self):
        for field, value in (
            ("name", "mixed"),
            ("context", {"GITHUB_RUN_ID": "other", "GITHUB_RUN_ATTEMPT": "1"}),
            ("context", {"GITHUB_RUN_ID": "fixture", "GITHUB_RUN_ATTEMPT": "2"}),
            ("plan_sha256", "other-plan"),
            ("build_sha256", "other-build"),
        ):
            with self.subTest(field=field, value=value):
                self.receipt("postgres", **{field: value})
                with pytest.raises(ValueError, match="cleanup is unconfirmed"):
                    self.confirm()

    def test_unreadable_or_ambiguous_receipts_never_count_as_unstarted(self):
        path = self.results / "postgres.json"
        for content in (
            "{",
            "[]",
            '{"process_cleanup_confirmed":false,"process_cleanup_confirmed":true}',
            " " * (1024 * 1024 + 1),
        ):
            with self.subTest(content=content[:80]):
                path.write_text(content)
                with pytest.raises(ValueError, match=r"database|cleanup|Expecting property name"):
                    self.confirm()
        path.unlink()
        path.symlink_to(self.results / "missing.json")
        with pytest.raises(ValueError, match="invalid nested cleanup receipt"):
            self.confirm()
        path.unlink()
        self.receipt("redis")
        path.symlink_to(self.results / "redis.json")
        with pytest.raises(ValueError, match="invalid nested cleanup receipt"):
            self.confirm()
        path.unlink()
        path.mkdir()
        with pytest.raises(ValueError, match="invalid nested cleanup receipt"):
            self.confirm()

    def test_fifo_receipt_is_rejected_before_any_read(self):
        path = self.results / "postgres.json"
        os.mkfifo(path)
        # A broken consumer fails immediately instead of blocking the test on
        # the actual FIFO. The repaired consumer rejects its real inode first.
        with mock.patch.object(execution, "read", side_effect=AssertionError) as read:
            with pytest.raises(ValueError, match="invalid nested cleanup receipt"):
                self.confirm()
            read.assert_not_called()

    def test_receipt_metadata_error_is_not_treated_as_absence(self):
        error = PermissionError()
        with (
            mock.patch.object(Path, "lstat", side_effect=error),
            pytest.raises(PermissionError) as caught,
        ):
            self.confirm()
        self.assertIs(caught.value, error)

    def test_fifo_replacement_after_metadata_read_is_rejected_without_blocking(self):
        self.receipt("postgres")
        path = self.results / "postgres.json"
        original_open = os.open

        def replace_then_open(selected, flags):
            self.assertEqual(selected, path)
            # Refuse the fixture operation before creating a FIFO if a regression
            # removes the nonblocking open; a failing test must not hang itself.
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_NOFOLLOW)
            path.unlink()
            os.mkfifo(path)
            return original_open(selected, flags)

        with mock.patch.object(execution.os, "open", side_effect=replace_then_open) as opened:
            with pytest.raises(ValueError, match="invalid nested cleanup receipt"):
                self.confirm()
            opened.assert_called_once()

    def run_lane(self, command):
        cancelled = threading.Event()
        with (
            mock.patch.object(lanes, "command", side_effect=command),
            mock.patch.object(lanes, "capture", return_value=""),
            mock.patch.object(
                lanes,
                "inspect_suppliers",
                return_value={"postgres": {"container": "a" * 64}},
            ),
        ):
            status = lanes.lane_run(
                "postgres", self.plan_path, self.results, self.directory / "work", cancelled
            )
        row = json.loads((self.results / "lane-postgres.json").read_text())
        return status, row, cancelled

    def test_nested_uncertainty_defers_teardown_after_direct_command_returns(self):
        calls = []

        def command(argv, env, log, event, *, timeout):
            calls.append(argv)
            if argv[0] == "bash":
                self.receipt("postgres", process_cleanup_confirmed=False)
            return 0

        status, row, cancelled = self.run_lane(command)
        self.assertEqual(status, 1)
        self.assertTrue(cancelled.is_set())
        self.assertFalse(row["cleanup"] or row["complete"])
        self.assertIn("nested process cleanup is unconfirmed", row["cleanup_deferred"])
        self.assertFalse(any("down" in argv for argv in calls))
        self.assertTrue(Path(row["recovery"]["compose_file"]).is_file())
        self.assertEqual(row["recovery"]["execution_receipts"], str(self.results))

    def test_failed_but_confirmed_nested_execution_still_tears_down(self):
        calls = []

        def command(argv, env, log, event, *, timeout):
            calls.append(argv)
            if argv[0] == "bash":
                self.receipt("postgres")
                return 37
            return 0

        status, row, cancelled = self.run_lane(command)
        self.assertEqual(status, 1)
        self.assertTrue(cancelled.is_set())
        self.assertTrue(row["cleanup"])
        self.assertFalse(row["complete"])
        self.assertEqual(row["returncode"], 37)
        self.assertEqual(sum("down" in argv for argv in calls), 1)
        self.assertNotIn("cleanup_deferred", row)

    def test_live_direct_process_with_unconfirmed_stop_keeps_dependencies(self):
        real_command = lanes.command
        processes = []
        calls = []

        class CancelAfterSpawn(threading.Event):
            def wait(self, timeout=None):
                self.set()
                return True

        def unconfirmed_stop(process):
            processes.append(process)
            self.assertIsNone(process.poll())
            raise TimeoutError

        def command(argv, env, log, event, *, timeout):
            calls.append(argv)
            if argv[0] != "bash":
                return 0
            return real_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                env,
                log,
                CancelAfterSpawn(),
                timeout=5,
            )

        try:
            with mock.patch.object(lanes, "stop", side_effect=unconfirmed_stop):
                status, row, cancelled = self.run_lane(command)
            self.assertEqual(len(processes), 1)
            process = processes[0]
            self.assertIsNone(process.poll(), "fixture must expose a still-live owned process")
            self.assertEqual(status, 1)
            self.assertTrue(cancelled.is_set())
            self.assertFalse(any("down" in argv for argv in calls))
            self.assertFalse(row["cleanup"] or row["complete"])
            self.assertEqual(row["unconfirmed_groups"], [process.pid])
            self.assertIn("outer command group", row["cleanup_deferred"])
            self.assertTrue(Path(row["recovery"]["compose_file"]).is_file())
        finally:
            # Independent fixture ownership must clean up even on the old defect.
            for process in processes:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        for process in processes:
            self.assertFalse(execution.group_running(process.pid))


if __name__ == "__main__":
    unittest.main()
