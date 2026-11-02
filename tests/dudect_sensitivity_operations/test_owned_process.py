# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009, PT027
import os  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from owned_process import OwnedProcess, attach_guard, retire_guard, start_ticks


class OwnedProcessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.script = Path(self.directory.name) / "guard.py"
        self.script.write_text(
            "import signal,time,sys\n"
            "if len(sys.argv)>1:signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "print('ready',flush=True)\ntime.sleep(30)\n"
        )

    def child(self, ignore=False):
        child = subprocess.Popen(  # noqa: S603 -- explicit argv; artifact validation precedes execution
            [sys.executable, "-B", str(self.script), *(["ignore"] if ignore else [])],
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(child.stdout.close)
        self.addCleanup(lambda: child.wait(timeout=5))
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        self.assertEqual(child.stdout.readline().strip(), "ready")
        return child

    def attach(self, child):
        owned = OwnedProcess(child.pid, self.script, start_ticks(child.pid))
        self.addCleanup(owned.close)
        return owned

    def test_normal_termination_and_exit_are_descriptor_based(self):
        child = self.child()
        owned = self.attach(child)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("late proc read")):
            owned.terminate()
            self.assertEqual(owned.wait(2), "EXIT_OBSERVED_NOT_CHILD")
        self.assertEqual(child.wait(2), -signal.SIGTERM)

    def test_already_exited_after_attach_and_repeated_retirement(self):
        child = self.child()
        owned = self.attach(child)
        child.kill()
        child.wait(2)
        owned.terminate()
        self.assertEqual(owned.wait(2), "EXIT_OBSERVED_NOT_CHILD")
        owned.terminate()

    def test_wrong_start_or_script_refused_without_signal(self):
        for wrong_script, wrong_start in ((self.script, "0"), ("wrong.py", None)):
            child = self.child()
            with self.assertRaises(ValueError):
                OwnedProcess(child.pid, wrong_script, wrong_start or start_ticks(child.pid))
            self.assertIsNone(child.poll())

    def test_signal_never_uses_recycled_numeric_pid(self):
        child = self.child()
        owned = self.attach(child)
        with patch("os.kill", side_effect=AssertionError("numeric PID signal")):
            owned.terminate()
            owned.wait(2)

    def test_ignored_term_is_not_reported_as_exit(self):
        child = self.child(ignore=True)
        owned = self.attach(child)
        owned.terminate()
        with self.assertRaises(TimeoutError):
            owned.wait(0.02)
        self.assertIsNone(owned.poll())

    def test_invalid_timeout_and_closed_descriptor_refused(self):
        child = self.child()
        owned = self.attach(child)
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                owned.wait(timeout)
        owned.close()
        with self.assertRaises(ValueError):
            owned.poll()

    def test_attachment_read_error_closes_descriptor_and_does_not_signal(self):
        child = self.child()
        before = len(list(Path("/proc/self/fd").iterdir()))
        with patch.object(Path, "read_bytes", side_effect=PermissionError):  # noqa: SIM117 -- retain explicit owned-child and guard lifetimes
            with self.assertRaises(PermissionError):
                OwnedProcess(child.pid, self.script, start_ticks(child.pid))
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)
        self.assertIsNone(child.poll())

    def test_attachment_after_exit_refused(self):
        child = self.child()
        ticks = start_ticks(child.pid)
        child.kill()
        child.wait(2)
        with self.assertRaises(ProcessLookupError):
            OwnedProcess(child.pid, self.script, ticks)

    def launch_receipt(self, child):
        path = Path(self.directory.name) / "guard-process.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "owned-guard-process/1",
                    "pid": child.pid,
                    "script": str(self.script),
                    "start_ticks": start_ticks(child.pid),
                }
            )
        )
        return path

    def test_resumed_guard_retirement_uses_launch_identity_and_pidfd(self):
        child = self.child()
        owned = attach_guard(self.launch_receipt(child), self.script)
        self.addCleanup(owned.close)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("late identity read")):
            receipt = retire_guard(owned, actual_termination_verified=True)
        self.assertEqual(receipt["guard_exit"], "EXIT_OBSERVED_NOT_CHILD")
        self.assertFalse(receipt["guard_exit_code_known"])
        self.assertFalse(receipt["deadline_firing_claimed"])
        child.wait(2)

    def test_old_receipt_is_not_upgraded_from_numeric_pid(self):
        child = self.child()
        path = self.launch_receipt(child)
        receipt = json.loads(path.read_text())
        del receipt["start_ticks"]
        path.write_text(json.dumps(receipt))
        with self.assertRaises(ValueError):
            attach_guard(path, self.script)
        self.assertIsNone(child.poll())

    def test_resource_termination_required_before_retiring_guard(self):
        child = self.child()
        owned = self.attach(child)
        for unverified in (False, None, "true", 1):
            with self.assertRaises(ValueError):
                retire_guard(owned, actual_termination_verified=unverified)
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                retire_guard(owned, actual_termination_verified=True, timeout=timeout)
        self.assertIsNone(child.poll())

    def test_retirement_timeout_leaves_guard_unconfirmed(self):
        child = self.child(ignore=True)
        owned = attach_guard(self.launch_receipt(child), self.script)
        self.addCleanup(owned.close)
        with self.assertRaises(TimeoutError):
            retire_guard(owned, actual_termination_verified=True, timeout=0.02)
        self.assertIsNone(child.poll())


if __name__ == "__main__":
    unittest.main()
