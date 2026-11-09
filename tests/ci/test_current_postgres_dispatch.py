"""Actual runtime dispatch with simulated PG ownership and real cancellation state."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest also runs without pytest and under Python -O.
import ast
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))


class PostgresDispatchTests(unittest.TestCase):
    def setUp(self):
        owner = tempfile.TemporaryDirectory(prefix="aeg-pg-dispatch-")
        self.addCleanup(owner.cleanup)
        self.directory = Path(owner.name)
        self.pg = self.directory / "bin"
        self.data = self.directory / "data"
        self.cluster = {"data": self.data}
        self.record = {"test_generation": 1}
        self.postgres = mock.Mock()
        self.postgres.capture.return_value = self.record
        self.command = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "started", ""))
        spec = importlib.util.spec_from_file_location(
            "dispatch_current_process", ROOT / "tests/organizations/current_process.py"
        )
        self.process = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.process)
        previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        self.addCleanup(lambda: [signal.signal(s, handler) for s, handler in previous.items()])
        self.process.install_cancellation()
        path = ROOT / "tests/organizations/current_runtime.py"
        node = next(
            n
            for n in ast.parse(path.read_text()).body
            if isinstance(n, ast.FunctionDef) and n.name == "run"
        )
        values = {
            "pg": self.pg,
            "clusters": {"primary": self.cluster},
            "postgres_ownership": self.postgres,
            "run_owned": self.command,
            "root": self.directory,
            "env": dict(os.environ),
            "subprocess": subprocess,
            "check_cancellation": self.process.check_cancellation,
            "cleanup_scope": self.process.cleanup_scope,
        }
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), values)  # noqa: S102
        self.run = values["run"]

    def start(self):
        return self.run([self.pg / "pg_ctl", "-D", self.data, "-w", "start"], supplier=self.data)

    def stop(self, mode="immediate"):
        return self.run(
            [self.pg / "pg_ctl", "-D", self.data, "-w", "-t", "20", "-m", mode, "stop"],
            timeout=25,
        )

    def test_stop_uses_saved_owner_and_never_launches_numeric_pid_stop(self):
        self.start()
        self.command.reset_mock()
        for mode in ("fast", "immediate"):
            with self.subTest(mode=mode):
                result = self.stop(mode)
                self.assertEqual(result.returncode, 0)
                self.postgres.stop.assert_called_with(
                    self.pg, self.data, self.record, mode=mode, timeout=20
                )
                self.assertEqual(self.cluster["postgres_state"], "stopped")
        self.command.assert_not_called()

    def test_stop_failure_preserves_owner_and_blocks_restart(self):
        self.start()
        self.postgres.stop.side_effect = AssertionError("postmaster PID was reused")
        with self.assertRaisesRegex(AssertionError, "PID was reused"):
            self.stop()
        self.assertIs(self.cluster["postgres_owner"], self.record)
        self.assertEqual(self.cluster["postgres_state"], "unconfirmed")
        self.assertIn("PID was reused", self.cluster["postgres_ownership_error"])
        self.command.reset_mock()
        with self.assertRaisesRegex(RuntimeError, "unconfirmed or active"):
            self.start()
        self.command.assert_not_called()

    def test_late_start_cancellation_registers_owner_before_propagation(self):
        def complete_then_cancel(*_args, **_kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            self.process.check_cancellation()

        self.command.side_effect = complete_then_cancel
        with self.assertRaisesRegex(RuntimeError, "signal 15"):
            self.start()
        self.assertIs(self.cluster["postgres_owner"], self.record)
        self.assertEqual(self.cluster["postgres_state"], "running")
        self.assertTrue(self.process.cancellation_recorded())

    def test_signal_during_capture_is_checked_after_registration(self):
        def capture(*_args):
            os.kill(os.getpid(), signal.SIGTERM)
            return self.record

        self.postgres.capture.side_effect = capture
        with self.assertRaisesRegex(RuntimeError, "signal 15"):
            self.start()
        self.assertIs(self.cluster["postgres_owner"], self.record)
        self.assertEqual(self.cluster["postgres_state"], "running")

    def test_known_command_failure_and_output_survive_capture_failure(self):
        failed = subprocess.CompletedProcess([], 37, "partial stdout", "start stderr")
        self.command.return_value = failed
        self.postgres.capture.side_effect = AssertionError("no owned postmaster")
        self.assertIs(self.start(), failed)
        self.assertEqual(
            (failed.returncode, failed.stdout, failed.stderr),
            (37, "partial stdout", "start stderr"),
        )
        self.assertIsNone(self.cluster["postgres_owner"])
        self.assertEqual(self.cluster["postgres_state"], "unconfirmed")
        self.assertIn("no owned postmaster", self.cluster["postgres_ownership_error"])

    def test_capture_failure_keeps_primary_exception(self):
        failure = ValueError("original start failure")
        self.command.side_effect = failure
        self.postgres.capture.side_effect = PermissionError("procfs denied")
        with self.assertRaises(ValueError) as caught:
            self.start()
        self.assertIs(caught.exception, failure)
        self.assertIn("procfs denied", " ".join(failure.__notes__))
        self.assertIsNone(self.cluster["postgres_owner"])

    def test_successful_start_without_capture_remains_unconfirmed(self):
        self.postgres.capture.side_effect = AssertionError("role mismatch")
        with self.assertRaisesRegex(AssertionError, "role mismatch"):
            self.start()
        self.assertEqual(self.cluster["postgres_state"], "unconfirmed")
        self.assertIsNone(self.cluster["postgres_owner"])

    def test_stop_finishes_confirmation_before_cancellation_propagates(self):
        self.start()
        confirmed = []

        def stop(*_args, **_kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            self.process.check_cancellation()
            confirmed.append(True)

        self.postgres.stop.side_effect = stop
        with self.assertRaisesRegex(RuntimeError, "signal 15"):
            self.stop()
        self.assertEqual(confirmed, [True])
        self.assertEqual(self.cluster["postgres_state"], "stopped")
        self.assertIs(self.cluster["postgres_owner"], self.record)

    def test_restart_captures_new_generation_and_never_reuses_old_owner(self):
        self.start()
        self.stop("fast")
        second = {"test_generation": 2}
        self.postgres.capture.return_value = second
        self.start()
        self.assertEqual(self.cluster["postgres_generation"], 2)
        self.assertIs(self.cluster["postgres_owner"], second)
        self.stop()
        self.postgres.capture.side_effect = AssertionError("new owner unavailable")
        with self.assertRaisesRegex(AssertionError, "new owner unavailable"):
            self.start()
        self.assertEqual(self.cluster["postgres_generation"], 3)
        self.assertIsNone(self.cluster["postgres_owner"])
        self.assertEqual(self.cluster["postgres_state"], "unconfirmed")

    def test_untracked_and_malformed_controls_cannot_fall_back_to_pg_ctl(self):
        commands = (
            [self.pg / "pg_ctl", "stop", "-D", self.data],
            [self.pg / "pg_ctl", "-D", self.data, "stop"],
            [self.pg / "pg_ctl", "-D", self.data, "start"],
            [self.pg / "pg_ctl", "-D", self.data, "restart"],
            [
                self.pg / "pg_ctl",
                "-D",
                self.directory / "other",
                "-w",
                "-t",
                "20",
                "-m",
                "fast",
                "stop",
            ],
        )
        for command in commands:
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.run(command)
        with self.assertRaises(ValueError):
            self.run([], supplier=self.data)
        self.command.assert_not_called()
        self.postgres.stop.assert_not_called()
        self.postgres.capture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
