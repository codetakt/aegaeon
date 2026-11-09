"""Keep captured policy-command diagnostics after confirmed timeout cleanup."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest and independently owned real child processes.
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
sys.path[:0] = [str(ROOT / "scripts/ci"), str(ROOT / "scripts/validation")]
import database_execution as execution  # noqa: E402
import with_organization_userns as namespace  # noqa: E402


class NamespaceTimeoutDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.children = []
        self.captures = []
        self.records = []
        self.addCleanup(self.recover)
        self.enterContext(mock.patch.object(namespace, "_cancellation", None))
        self.enterContext(mock.patch.object(namespace, "_cleaning", False))
        self.enterContext(mock.patch.object(namespace, "_unconfirmed_groups", set()))
        previous = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        signal.signal(signal.SIGTERM, namespace.interrupted)

    def recover(self):
        for child in self.children:
            if execution.group_running(child.pid):
                execution.stop_process_group(child, grace=0.1)
            child.wait(timeout=3)

    def capture_case(self, *, cancel=False, failed_read=0):  # noqa: PLR0915 - one owned child and capture lifetime.
        ready = self.directory / "ready"
        script = self.directory / "child.py"
        script.write_text(
            "import os,time\nfrom pathlib import Path\n"
            "os.write(1,b'partial stdout\\n')\n"
            "os.write(2,b'partial stderr\\n')\n"
            f"Path({str(ready)!r}).write_text('ready')\n"
            "time.sleep(10)\n"
        )
        command = [sys.executable, str(script)]
        real_spawn = subprocess.Popen
        real_file = tempfile.TemporaryFile
        real_wait = namespace.wait_command
        real_read = os.pread
        primary = None
        reads = 0

        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            self.children.append(child)
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertTrue(ready.exists())
            return child

        def capture_file(*args, **kwargs):
            stream = real_file(*args, **kwargs)
            self.captures.append(stream)
            return stream

        def wait(*args, **kwargs):
            nonlocal primary
            if cancel:
                os.kill(os.getpid(), signal.SIGTERM)
            try:
                return real_wait(*args, **kwargs)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                primary = error
                raise

        def read(*args):
            nonlocal reads
            reads += 1
            if reads == failed_read:
                raise OSError("injected diagnostic read failure")  # noqa: EM101, TRY003
            return real_read(*args)

        with (
            mock.patch.object(namespace.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(namespace.tempfile, "TemporaryFile", side_effect=capture_file),
            mock.patch.object(namespace, "wait_command", side_effect=wait),
            mock.patch.object(namespace.os, "pread", side_effect=read),
            self.assertRaises(RuntimeError if cancel else subprocess.TimeoutExpired) as raised,
        ):
            namespace.execute(command, timeout=0.15)
        error = raised.exception
        child = self.children[-1]
        result = getattr(error, "command_result", None)
        record = {
            "pid": child.pid,
            "cancel": cancel,
            "failed_read": failed_read,
            "exception": type(error).__name__,
            "primary_preserved": error is primary,
            "command_result": vars(result) if result is not None else None,
            "notes": getattr(error, "__notes__", []),
            "group_gone": not execution.group_running(child.pid),
            "unconfirmed": sorted(namespace._unconfirmed_groups),
            "captures_closed": all(stream.closed for stream in self.captures),
        }
        self.records.append(record)
        self.assertIs(error, primary, record)
        self.assertTrue(record["group_gone"], record)
        self.assertEqual(record["unconfirmed"], [], record)
        self.assertEqual(len(self.captures), 2, record)
        self.assertTrue(record["captures_closed"], record)
        self.assertIsNotNone(result, record)
        self.assertIsNone(result.returncode, record)
        return error, result, record

    def test_real_timeout_preserves_both_streams_after_confirmed_stop(self):
        error, result, record = self.capture_case()
        self.assertEqual(error.output, "partial stdout\n", record)
        self.assertEqual(error.stderr, "partial stderr\n", record)
        self.assertEqual(result.stdout, error.output, record)
        self.assertEqual(result.stderr, error.stderr, record)

    def test_real_cancellation_preserves_both_streams_after_confirmed_stop(self):
        _, result, record = self.capture_case(cancel=True)
        self.assertEqual(result.stdout, "partial stdout\n", record)
        self.assertEqual(result.stderr, "partial stderr\n", record)
        self.assertTrue(namespace._cancellation, record)

    def test_partial_capture_failure_preserves_timeout_and_completed_read(self):
        error, result, record = self.capture_case(failed_read=2)
        self.assertEqual(error.output, "partial stdout\n", record)
        self.assertEqual(result.stdout, error.output, record)
        self.assertIsNone(error.stderr, record)
        self.assertIsNone(result.stderr, record)
        self.assertIn("command diagnostic capture failed: OSError", record["notes"])

    def test_first_capture_failure_preserves_cancellation(self):
        _, result, record = self.capture_case(cancel=True, failed_read=1)
        self.assertIsNone(result.stdout, record)
        self.assertIsNone(result.stderr, record)
        self.assertIn("command diagnostic capture failed: OSError", record["notes"])


if __name__ == "__main__":
    unittest.main()
