"""Keep dependencies available until every started process owner confirms cleanup."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions survive Python -O.
import contextlib
import json
import os
import signal
import subprocess
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
            "suites": dict.fromkeys(execution.selectors()),
            "auxiliaries": list(execution.AUXILIARIES),
        }
        self.results = self.directory / "results"
        self.results.mkdir()
        self.results_identity = self.enterContext(execution.pinned_results_directory(self.results))
        # Package discovery and native execution have separate existing tests.
        # These fixtures exercise the real cleanup consumer and its receipt bytes.
        self.enterContext(mock.patch.object(execution, "load_plan", return_value=self.plan))
        self.enterContext(mock.patch.object(lanes, "load_plan", return_value=self.plan))
        execution.initialize_receipts(self.plan_path, self.results)

    def receipt(self, filename, **changes):
        row = {
            "name": filename,
            "context": self.plan["context"],
            "plan_sha256": execution.sha(self.plan_path),
            "build_sha256": self.plan["build_sha256"],
            "process_cleanup_confirmed": True,
            "execution_state": "started",
            "invocation_id": "a" * 32,
            # Failed tests can safely release dependencies after confirmed stop.
            "complete": False,
            "returncode": 37,
        }
        row.update(changes)
        (self.results / f"{filename}.json").write_text(json.dumps(row))
        return row

    def confirm(self, lane="postgres", *, require_all=False):
        execution.confirm_lane_cleanup(
            self.plan_path,
            self.results,
            lane,
            require_all=require_all,
            expected_identity=self.results_identity,
        )

    def test_missing_receipts_require_identity_captured_before_work(self):
        with pytest.raises(ValueError, match="pre-execution"):
            execution.confirm_lane_cleanup(self.plan_path, self.results, "postgres")

    def test_replacement_before_confirmation_cannot_hide_unconfirmed_receipt(self):
        self.receipt("postgres", process_cleanup_confirmed=False)
        self.results.rename(self.directory / "original-results")
        self.results.mkdir()
        with pytest.raises(ValueError, match="directory changed"):
            self.confirm()

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
        path.unlink()
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
            mock.patch.object(execution.os, "stat", side_effect=error),
            pytest.raises(PermissionError) as caught,
        ):
            self.confirm()
        self.assertIs(caught.value, error)

    def test_fifo_replacement_after_metadata_read_is_rejected_without_blocking(self):
        self.receipt("postgres")
        path = self.results / "postgres.json"
        original_open = os.open

        def replace_then_open(selected, flags, **kwargs):
            if selected != path.name:
                return original_open(selected, flags, **kwargs)
            self.assertEqual(selected, path.name)
            # Refuse the fixture operation before creating a FIFO if a regression
            # removes the nonblocking open; a failing test must not hang itself.
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_NOFOLLOW)
            path.unlink()
            os.mkfifo(path)
            return original_open(selected, flags, **kwargs)

        with mock.patch.object(execution.os, "open", side_effect=replace_then_open) as opened:
            with pytest.raises(ValueError, match="invalid nested cleanup receipt"):
                self.confirm()
            self.assertEqual(opened.call_count, 4)

    def test_unavailable_results_directory_is_never_unstarted_work(self):
        for path in self.results.iterdir():
            path.unlink()
        self.results.rmdir()
        with pytest.raises(FileNotFoundError):
            self.confirm()
        self.results.symlink_to(self.directory / "missing")
        with pytest.raises(NotADirectoryError):
            self.confirm()
        self.results.unlink()
        alternate = self.directory / "alternate"
        alternate.mkdir()
        self.results.symlink_to(alternate)
        with pytest.raises(NotADirectoryError):
            self.confirm()
        self.results.unlink()
        self.results.write_text("not a directory")
        with pytest.raises(NotADirectoryError):
            self.confirm()

    def test_replaced_results_directory_cannot_certify_missing_receipts(self):
        original_stat = os.stat
        replaced = False

        def replace_then_stat(path, **kwargs):
            nonlocal replaced
            if kwargs.get("dir_fd") is not None and not replaced:
                replaced = True
                self.results.rename(self.directory / "original-results")
                self.results.mkdir()
            return original_stat(path, **kwargs)

        with (
            mock.patch.object(execution.os, "stat", side_effect=replace_then_stat),
            pytest.raises(ValueError, match="directory changed"),
        ):
            self.confirm()
        self.assertTrue(replaced)

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

    def test_directory_replacement_during_work_retains_suppliers(self):
        calls = []
        original = self.directory / "original-results"

        def command(argv, env, log, event, *, timeout):
            calls.append(argv)
            if argv[0] == "bash":
                self.receipt("postgres", process_cleanup_confirmed=False)
                self.results.rename(original)
                self.results.mkdir()
            return 0

        status, row, cancelled = self.run_lane(command)
        self.assertEqual(status, 1)
        self.assertTrue(cancelled.is_set())
        self.assertFalse(row["cleanup"] or row["complete"])
        self.assertIn("directory changed", row["cleanup_deferred"])
        self.assertFalse(any("down" in argv for argv in calls))
        self.assertFalse(
            json.loads((original / "postgres.json").read_text())["process_cleanup_confirmed"]
        )
        self.assertEqual(
            row["results_directory_identity"],
            {"device": self.results_identity[0], "inode": self.results_identity[1]},
        )

    def run_lane_with_missing_publication(self, command, cancelled):
        with (
            mock.patch.object(lanes, "command", side_effect=command),
            mock.patch.object(lanes, "capture", return_value=""),
            mock.patch.object(
                lanes,
                "inspect_suppliers",
                return_value={"postgres": {"container": "a" * 64}},
            ),
        ):
            return lanes.lane_run(
                "postgres", self.plan_path, self.results, self.directory / "work", cancelled
            )

    def check_deleted_results(self, outcome):  # noqa: PLR0915 - one deletion/persistence boundary
        calls = []
        directory = None

        def command(argv, env, log, event, *, timeout):
            nonlocal directory
            calls.append(argv)
            directory = Path(env["DEV_COMPOSE_FILE"]).parent
            if "up" in argv:
                initial = json.loads((directory / "recovery.json").read_text())
                self.assertFalse(initial["complete"] or initial["cleanup"])
            if argv[0] == "bash":
                for item in self.results.iterdir():
                    item.unlink()
                self.results.rmdir()
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
            return 0

        cancelled = threading.Event()
        self.assertEqual(self.run_lane_with_missing_publication(command, cancelled), 1)
        self.assertTrue(cancelled.is_set())
        self.assertFalse(self.results.exists())
        self.assertFalse(any("down" in argv for argv in calls))
        self.assertIsNotNone(directory)
        recovery = directory / "recovery.json"
        row = json.loads(recovery.read_text())
        self.assertEqual(recovery.stat().st_mode & 0o777, 0o600)
        self.assertFalse(row["complete"] or row["cleanup"])
        self.assertIn("FileNotFoundError", row["cleanup_deferred"])
        self.assertIn("FileNotFoundError", row["receipt_error"])
        self.assertEqual(row["returncode"], 1 if isinstance(outcome, Exception) else outcome)
        if isinstance(outcome, Exception):
            self.assertEqual(row["error"], "RuntimeError: original work failure")
        self.assertTrue(Path(row["recovery"]["compose_file"]).is_file())
        self.assertEqual(row["recovery"]["execution_receipts"], str(self.results))
        self.assertEqual(row["plan_sha256"], execution.sha(self.plan_path))
        self.assertEqual(row["context"], self.plan["context"])
        self.results.mkdir()
        execution.initialize_receipts(self.plan_path, self.results)

    def test_deleted_results_preserves_recovery_and_original_outcome(self):
        for outcome in (0, 37, RuntimeError("original work failure")):
            with self.subTest(outcome=outcome):
                self.check_deleted_results(outcome)

    def test_initial_recovery_write_failure_starts_no_supplier(self):
        cancelled = threading.Event()
        failure = OSError("initial recovery storage failure")
        with (
            mock.patch.object(lanes, "replace_receipt", side_effect=failure),
            mock.patch.object(lanes, "command") as command,
            pytest.raises(OSError, match="initial recovery storage failure") as caught,
        ):
            lanes.lane_run(
                "postgres", self.plan_path, self.results, self.directory / "work", cancelled
            )
        self.assertIs(caught.value, failure)
        self.assertTrue(cancelled.is_set())
        command.assert_not_called()
        self.assertFalse((self.results / "lane-postgres.json").exists())

    def test_terminal_atomic_write_failure_keeps_initial_record_and_error(self):
        cancelled = threading.Event()
        original_replace = os.replace
        initial = {}
        failure = OSError("terminal atomic replace failed")

        def command(argv, env, log, event, *, timeout):
            if argv[0] == "bash":
                directory = Path(env["DEV_COMPOSE_FILE"]).parent
                initial["path"] = directory / "recovery.json"
                initial["bytes"] = initial["path"].read_bytes()
                raise lanes.UnconfirmedCommandCleanupError(123)
            self.assertNotIn("down", argv)
            return 0

        def replace(source, destination, **kwargs):
            if initial:
                raise failure
            return original_replace(source, destination, **kwargs)

        with (
            mock.patch.object(execution.os, "replace", side_effect=replace),
            pytest.raises(OSError, match="terminal atomic replace failed") as caught,
        ):
            self.run_lane_with_missing_publication(command, cancelled)
        self.assertIs(caught.value, failure)
        self.assertTrue(cancelled.is_set())
        self.assertEqual(initial["path"].read_bytes(), initial["bytes"])
        self.assertFalse(json.loads(initial["bytes"])["complete"])
        self.assertFalse(list(initial["path"].parent.glob(".*.tmp")))
        self.assertIn("returncode=1", " ".join(failure.__notes__))
        self.assertIn("UnconfirmedCommandCleanupError", " ".join(failure.__notes__))

    def test_results_write_failure_never_certifies_fallback_completion(self):
        cancelled = threading.Event()
        receipt = self.results / "lane-postgres.json"
        original_write = Path.write_text
        original_replace = os.replace
        writes = []
        calls = []
        failure = PermissionError("results publication refused")

        def command(argv, env, log, event, *, timeout):
            calls.append(argv)
            return 0

        def write(path, text, **kwargs):
            if path == receipt:
                writes.append(path)
                raise failure
            return original_write(path, text, **kwargs)

        def replace(source, destination, **kwargs):
            if writes:
                self.assertTrue(cancelled.is_set())
            return original_replace(source, destination, **kwargs)

        with (
            mock.patch.object(Path, "write_text", write),
            mock.patch.object(execution.os, "replace", side_effect=replace),
        ):
            self.assertEqual(self.run_lane_with_missing_publication(command, cancelled), 1)
        self.assertTrue(cancelled.is_set())
        self.assertEqual(sum("down" in argv for argv in calls), 1)
        recovery = next((self.directory / "work").glob("*/recovery.json"))
        row = json.loads(recovery.read_text())
        self.assertFalse(row["complete"])
        self.assertTrue(row["cleanup"])
        self.assertEqual(row["returncode"], 0)
        self.assertIn("PermissionError", row["receipt_error"])
        self.assertFalse(json.loads(receipt.read_text())["complete"])

    def test_failed_results_and_recovery_updates_keep_diagnostic_false(self):
        directory = self.directory / "project"
        directory.mkdir()
        receipt = self.results / "removed" / "lane-postgres.json"
        record = {
            "name": "lane-postgres",
            "project": "owned-project",
            "complete": True,
            "cleanup": True,
            "returncode": 0,
        }
        cancelled = threading.Event()
        original_replace = os.replace
        replacements = 0
        failure = OSError("recovery update refused after results loss")

        def replace(source, destination, **kwargs):
            nonlocal replacements
            replacements += 1
            if replacements == 2:
                self.assertTrue(cancelled.is_set())
                raise failure
            return original_replace(source, destination, **kwargs)

        with (
            mock.patch.object(execution.os, "replace", side_effect=replace),
            pytest.raises(OSError, match="recovery update refused") as caught,
        ):
            lanes.publish_lane_receipt(directory, receipt, record, cancelled)
        self.assertIs(caught.value, failure)
        self.assertIsInstance(failure.__context__, FileNotFoundError)
        self.assertFalse(record["complete"])
        self.assertTrue(cancelled.is_set())
        row = json.loads((directory / "recovery.json").read_text())
        self.assertFalse(row["complete"])
        self.assertTrue(row["cleanup"])
        self.assertEqual(row["returncode"], 0)
        self.assertIn("FileNotFoundError", " ".join(failure.__notes__))
        self.assertFalse(list(directory.glob(".*.tmp")))

    def test_later_lane_rejects_directory_changed_after_main_capture(self):
        self.results.rename(self.directory / "original-results")
        self.results.mkdir()
        with (
            mock.patch.object(lanes, "command") as command,
            pytest.raises(ValueError, match="directory changed"),
        ):
            lanes.lane_run(
                "postgres",
                self.plan_path,
                self.results,
                self.directory / "work",
                threading.Event(),
                expected_identity=self.results_identity,
            )
        command.assert_not_called()

    def test_deleted_started_receipt_retains_suppliers_with_live_nested_child(self):  # noqa: PLR0915 - one owned-child boundary
        processes = []
        calls = []
        original_popen = subprocess.Popen
        owned_command = [sys.executable, "-c", "import time; time.sleep(30)"]
        checkpoints = 0
        work_error = ValueError("controlled post-spawn work error")
        stop_error = TimeoutError("controlled nested stop uncertainty")

        def created(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        def interrupted():
            nonlocal checkpoints
            checkpoints += 1
            if checkpoints == 3:
                raise work_error

        def unconfirmed(process, **kwargs):
            self.assertIsNone(process.poll())
            raise stop_error

        def command(argv, env, log, event, *, timeout):
            calls.append(argv)
            if argv[0] != "bash":
                return 0
            with (
                mock.patch.object(execution, "bind_package"),
                mock.patch.object(execution, "owned_command", return_value=owned_command),
                mock.patch.object(execution, "owned_cwd", return_value=self.directory),
                mock.patch.object(execution, "check_cancellation", side_effect=interrupted),
                mock.patch.object(execution, "stop_process_group", side_effect=unconfirmed),
                mock.patch.object(execution.subprocess, "Popen", side_effect=created),
                pytest.raises(TimeoutError),
            ):
                execution.execute(
                    self.plan_path, self.results, "postgres", owned_command, test_suite=True
                )
            receipt = self.results / "postgres.json"
            self.assertIs(json.loads(receipt.read_text())["process_cleanup_confirmed"], False)
            receipt.unlink()
            return 37

        try:
            status, row, cancelled = self.run_lane(command)
            self.assertEqual(len(processes), 1)
            self.assertIsNone(processes[0].poll())
            self.assertEqual(status, 1)
            self.assertTrue(cancelled.is_set())
            self.assertFalse(row["cleanup"] or row["complete"])
            self.assertIn("no cleanup receipt: postgres", row["cleanup_deferred"])
            self.assertFalse(any("down" in argv for argv in calls))
            self.assertTrue(Path(row["recovery"]["compose_file"]).is_file())
        finally:
            for process in processes:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
                if process.stdout is not None:
                    process.stdout.close()
        for process in processes:
            self.assertFalse(execution.group_running(process.pid))

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

    def test_capture_stop_uncertainty_defers_lane_supplier_teardown(self):  # noqa: PLR0915 - one owned-child and teardown-refusal boundary
        processes, calls, errors = [], [], []
        real_capture = lanes.capture

        class CancelOnWait(threading.Event):
            def wait(self, timeout=None):
                self.set()
                return True

        cancelled = CancelOnWait()

        def unconfirmed_stop(process):
            processes.append(process)
            self.assertIsNone(process.poll())
            message = "capture stop unconfirmed"
            raise TimeoutError(message)

        def capture(argv, env, *, cancelled=None):
            calls.append(argv)
            self.assertIs(cancelled, event)
            try:
                return real_capture(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    env,
                    cancelled=cancelled,
                )
            except lanes.UnconfirmedCommandCleanupError as error:
                errors.append(error)
                raise

        event = cancelled
        try:
            with (
                mock.patch.object(lanes, "command", return_value=0) as command,
                mock.patch.object(lanes, "capture", side_effect=capture),
                mock.patch.object(lanes, "stop", side_effect=unconfirmed_stop),
            ):
                status = lanes.lane_run(
                    "postgres", self.plan_path, self.results, self.directory / "work", event
                )
            row = json.loads((self.results / "lane-postgres.json").read_text())
            self.assertEqual(status, 1)
            self.assertTrue(event.is_set())
            self.assertEqual(len(processes), 1)
            self.assertEqual(len(calls), 1)
            self.assertIsNone(processes[0].poll())
            self.assertEqual(row["unconfirmed_groups"], [processes[0].pid])
            self.assertFalse(row["cleanup"] or row["complete"])
            self.assertIn("outer command group", row["cleanup_deferred"])
            self.assertTrue(Path(row["recovery"]["compose_file"]).is_file())
            self.assertEqual(command.call_count, 1)  # Only the simulated supplier start.
            self.assertIsInstance(errors[0].__cause__, TimeoutError)
            self.assertIsInstance(errors[0].__cause__.__context__, InterruptedError)
        finally:
            for process in processes:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        for process in processes:
            self.assertFalse(execution.group_running(process.pid))

    def test_cleanup_capture_uncertainty_cannot_report_supplier_success(self):
        record = {"cleanup": False}
        failure = lanes.UnconfirmedCommandCleanupError(12345)
        with (
            mock.patch.object(lanes, "command", return_value=0) as command,
            mock.patch.object(lanes, "capture", side_effect=failure) as capture,
        ):
            lanes.cleanup_suppliers(["compose"], {}, self.directory, "owned-project", record)
        self.assertFalse(command.call_args.args[3].is_set())
        self.assertEqual(capture.call_count, 1)
        self.assertNotIn("cancelled", capture.call_args.kwargs)
        self.assertFalse(record["cleanup"])
        self.assertEqual(record["unconfirmed_groups"], [12345])
        self.assertIn("UnconfirmedCommandCleanupError", record["cleanup_error"])

    def test_capture_preserves_nonzero_when_cancellation_arrives_during_stop(self):
        original_stop = lanes.stop
        for code in (0, 37):
            with self.subTest(returncode=code):
                processes = []
                cancelled = threading.Event()
                argv = [sys.executable, "-c", f"print('captured output'); raise SystemExit({code})"]

                def stop(process, processes=processes, code=code, cancelled=cancelled):
                    processes.append(process)
                    self.assertEqual(process.poll(), code)
                    cancelled.set()
                    original_stop(process)

                expected = subprocess.CalledProcessError if code else InterruptedError
                try:
                    with (
                        mock.patch.object(lanes, "stop", side_effect=stop),
                        pytest.raises(expected) as caught,
                    ):
                        lanes.capture(argv, dict(os.environ), cancelled=cancelled)
                    if code:
                        self.assertEqual(caught.value.returncode, 37)
                        self.assertEqual(caught.value.cmd, argv)
                        self.assertEqual(caught.value.output, "captured output\n")
                finally:
                    for process in processes:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=2)
                self.assertFalse(execution.group_running(processes[-1].pid))


if __name__ == "__main__":
    unittest.main()
