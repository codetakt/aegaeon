"""Real owned-command failures retain output after confirmed cleanup."""

from __future__ import annotations

# ruff: noqa: PT009 - unittest and independently reclaimed owned children.
import contextlib
import importlib.util
import io
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
import database_execution as execution  # noqa: E402


class CurrentProcessTimeoutDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.children = []
        self.records = []
        self.real_popen = subprocess.Popen
        self.addCleanup(self.recover)
        spec = importlib.util.spec_from_file_location(
            "timeout_current_process", ROOT / "tests/organizations/current_process.py"
        )
        self.current = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.current)
        previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        self.addCleanup(lambda: [signal.signal(s, handler) for s, handler in previous.items()])
        self.current.install_cancellation()

    def recover(self):
        for child in self.children:
            execution.stop_process_group(child, grace=0.1)

    def failure_case(  # noqa: C901, PLR0915 - one bounded actual-child observation.
        self, kind="timeout", *, private=False, fail_read=None, supplier=False
    ):
        ready = self.directory / "ready"
        ready.unlink(missing_ok=True)
        script = self.directory / "child.py"
        script.write_text(
            "import os,time\nfrom pathlib import Path\n"
            "os.write(1,b'partial stdout');os.write(2,b'partial stderr')\n"
            f"Path({str(ready)!r}).write_text('ready')\n"
            + ("time.sleep(10)\n" if kind in ("timeout", "cancel") else "")
        )
        command = [sys.executable, str(script)]
        private_log = self.directory / "private.log" if private else None
        if private_log:
            private_log.touch(mode=0o600)
        files, primary = [], []
        real_wait, real_stop, real_pread = (
            self.current.wait_owned,
            self.current.stop_owned,
            os.pread,
        )
        stop_confirmed, reads = [], []

        def spawn(*args, **kwargs):
            child = self.real_popen(*args, **kwargs)
            self.children.append(child)
            files.extend([kwargs["stdout"], kwargs["stderr"]])
            return child

        def ready_before_wait(_child):
            until = time.monotonic() + 2
            while not ready.exists() and time.monotonic() < until:
                time.sleep(0.005)
            self.assertTrue(ready.exists())

        def wait(*args, **kwargs):
            try:
                if kind == "cancel":
                    os.kill(os.getpid(), signal.SIGTERM)
                result = real_wait(*args, **kwargs)
                if supplier:
                    os.kill(os.getpid(), signal.SIGTERM)
                    primary.append(self.current._cancellation)
                return result  # noqa: TRY300 - capture the original wait failure and signal together.
            except BaseException as error:
                primary.append(error)
                raise

        def stop(child):
            real_stop(child)
            stop_confirmed.append(not execution.group_running(child.pid))
            if kind == "late-cancel":
                os.kill(os.getpid(), signal.SIGTERM)
                primary.append(self.current._cancellation)

        def pread(*args):
            reads.append(True)
            if len(reads) == fail_read:
                raise OSError("injected diagnostic read failure")  # noqa: EM101, TRY003
            return real_pread(*args)

        public_output = io.StringIO()
        error = None
        with (
            mock.patch.object(self.current.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(self.current, "wait_owned", side_effect=wait),
            mock.patch.object(self.current, "stop_owned", side_effect=stop),
            mock.patch.object(self.current.os, "pread", side_effect=pread),
            contextlib.redirect_stdout(public_output),
            contextlib.redirect_stderr(public_output),
        ):
            try:
                self.current.run_owned(
                    command,
                    root=self.directory,
                    env=dict(os.environ),
                    timeout=0.2 if kind == "timeout" else 3,
                    before_wait=ready_before_wait,
                    private_log=private_log,
                    retain_supplier=supplier,
                )
            except BaseException as failure:  # noqa: BLE001 - retain all observed failure kinds.
                error = failure
        child = self.children[-1]
        result = getattr(error, "command_result", None)
        record = {
            "kind": kind,
            "private": private,
            "fail_read": fail_read,
            "supplier": supplier,
            "pid": child.pid,
            "error": type(error).__name__,
            "primary_preserved": bool(primary) and error is primary[0],
            "cause": type(error.__cause__).__name__ if error else None,
            "command_result": vars(result) if result is not None else None,
            "notes": getattr(error, "__notes__", []),
            "stop_confirmed": stop_confirmed,
            "unconfirmed_groups": self.current.unconfirmed_groups(),
            "supplier_groups": self.current.supplier_start_groups(),
            "group_live_before_independent_cleanup": execution.group_running(child.pid),
            "files_closed": all(file.closed for file in files),
            "read_calls": len(reads),
            "public_output": public_output.getvalue(),
        }
        self.records.append(record)
        self.assertIsNotNone(error, record)
        self.assertTrue(record["primary_preserved"], record)
        self.assertIsNone(error.__cause__, record)
        self.assertEqual(stop_confirmed, [] if supplier else [True], record)
        self.assertEqual(record["unconfirmed_groups"], [], record)
        self.assertEqual(record["supplier_groups"], [child.pid] if supplier else [], record)
        self.assertFalse(record["group_live_before_independent_cleanup"], record)
        self.assertTrue(record["files_closed"], record)
        self.assertEqual(record["public_output"], "", record)
        return error, result, record, private_log

    def assert_streams(self, result, record, *, status=None):
        self.assertIsNotNone(result, record)
        self.assertEqual(result.returncode, status, record)
        self.assertEqual(result.stdout, "partial stdout", record)
        self.assertEqual(result.stderr, "partial stderr", record)

    def test_timeout_preserves_partial_streams_after_confirmed_cleanup(self):
        error, result, record, _ = self.failure_case()
        self.assertIsInstance(error, subprocess.TimeoutExpired, record)
        self.assertEqual(error.output, "partial stdout", record)
        self.assertEqual(error.stderr, "partial stderr", record)
        self.assert_streams(result, record)

    def test_private_timeout_retains_only_private_file(self):
        error, result, record, private_log = self.failure_case(private=True)
        self.assertIsInstance(error, subprocess.TimeoutExpired, record)
        self.assertEqual(private_log.read_text(), "partial stdoutpartial stderr")
        self.assertEqual(private_log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(getattr(error, "private_log", None), str(private_log), record)
        self.assertIsNotNone(result, record)
        self.assertIsNone(result.returncode, record)
        self.assertIsNone(result.stdout, record)
        self.assertIsNone(result.stderr, record)
        self.assertIsNone(error.output, record)
        self.assertIsNone(error.stderr, record)
        self.assertEqual(record["read_calls"], 0, record)
        for text in (str(error), repr(error), repr(vars(error)), repr(record)):
            self.assertNotIn("partial stdout", text)
            self.assertNotIn("partial stderr", text)

    def test_cancellation_preserves_partial_streams_after_confirmed_cleanup(self):
        error, result, record, _ = self.failure_case("cancel")
        self.assertIsInstance(error, RuntimeError, record)
        self.assertEqual(str(error), "current-runtime fixture interrupted by signal 15")
        self.assert_streams(result, record)

    def test_late_cancellation_preserves_successful_leader_streams(self):
        error, result, record, _ = self.failure_case("late-cancel")
        self.assertIsInstance(error, RuntimeError, record)
        self.assert_streams(result, record, status=0)

    def test_supplier_handoff_precedes_late_cancellation_diagnostics(self):
        # An actual exited starter, not a claim of an actual PostgreSQL supplier.
        error, result, record, _ = self.failure_case("supplier-cancel", supplier=True)
        self.assertIsInstance(error, RuntimeError, record)
        self.assert_streams(result, record, status=0)

    def test_capture_failure_preserves_timeout_and_available_diagnostics(self):
        for failed_read in (1, 2):
            with self.subTest(failed_read=failed_read):
                error, result, record, _ = self.failure_case(fail_read=failed_read)
                self.assertIsInstance(error, subprocess.TimeoutExpired, record)
                self.assertIsNotNone(result, record)
                self.assertIsNone(result.returncode, record)
                self.assertEqual(result.stdout, None if failed_read == 1 else "partial stdout")
                self.assertEqual(error.output, result.stdout)
                self.assertIsNone(result.stderr, record)
                self.assertIsNone(error.stderr, record)
                self.assertIn("command diagnostic capture failed: OSError", record["notes"])


if __name__ == "__main__":
    unittest.main()
