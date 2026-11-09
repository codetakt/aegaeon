"""Retain command failures when namespace work cleanup cannot be confirmed."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest assertions remain active under Python -O.
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts/ci"), str(ROOT / "scripts/validation")]
import database_execution as execution  # noqa: E402
import with_organization_userns as namespace  # noqa: E402


class NamespaceCommandCleanupFailureTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.children = []
        self.records = []
        self.addCleanup(self.recover)
        self.enterContext(mock.patch.object(namespace, "_cancellation", None))
        self.enterContext(mock.patch.object(namespace, "_cleaning", False))
        self.enterContext(mock.patch.object(namespace, "_unconfirmed_groups", set()))
        real_spawn = subprocess.Popen

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            self.children.append(process)
            return process

        self.enterContext(mock.patch.object(namespace.subprocess, "Popen", side_effect=spawn))
        self.stop_error = RuntimeError("injected cleanup confirmation failure")

    def recover(self):
        for process in self.children:
            execution.stop_process_group(process, grace=0.1)
            process.wait(timeout=3)
            self.assertFalse(Path(f"/proc/{process.pid}").exists())

    def refuse_confirmation(self, process, **_kwargs):
        # Real stop and wait precede the injected confirmation error. The
        # namespace owner must still retain its unconfirmed ownership record.
        execution.stop_process_group(process, grace=0.1)
        raise self.stop_error

    def assert_retained(self, error):
        child = self.children[-1]
        self.assertIn(child.pid, namespace._unconfirmed_groups)
        self.assertFalse(execution.group_running(child.pid))
        self.records.append(
            {
                "pid": child.pid,
                "status": child.returncode,
                "error": type(error).__name__,
                "returncode": getattr(error, "returncode", None),
                "cause": type(error.__cause__).__name__,
                "notes": getattr(error, "__notes__", []),
                "group_running": execution.group_running(child.pid),
                "unconfirmed": sorted(namespace._unconfirmed_groups),
            }
        )

    def test_known_failure_survives_cleanup_confirmation_error(self):
        command = [sys.executable, "-c", "raise SystemExit(37)"]
        with (
            mock.patch.object(namespace, "stop_owned", side_effect=self.refuse_confirmation),
            self.assertRaises(subprocess.CalledProcessError) as raised,
        ):
            namespace.run_command(command)
        self.assertEqual(raised.exception.returncode, 37)
        self.assertEqual(raised.exception.cmd, command)
        self.assertIs(raised.exception.__cause__, self.stop_error)
        self.assert_retained(raised.exception)

    def test_success_does_not_hide_cleanup_confirmation_error(self):
        with (
            mock.patch.object(namespace, "stop_owned", side_effect=self.refuse_confirmation),
            self.assertRaises(RuntimeError) as raised,
        ):
            namespace.run_command([sys.executable, "-c", "pass"])
        self.assertIs(raised.exception, self.stop_error)
        self.assert_retained(raised.exception)

    def test_timeout_remains_primary_when_cleanup_confirmation_also_fails(self):
        real_wait = namespace.wait_command
        primary = None

        def wait(process):
            nonlocal primary
            try:
                return real_wait(process, timeout=0.05)
            except subprocess.TimeoutExpired as error:
                primary = error
                raise

        with (
            mock.patch.object(namespace, "wait_command", side_effect=wait),
            mock.patch.object(namespace, "stop_owned", side_effect=self.refuse_confirmation),
            self.assertRaises(subprocess.TimeoutExpired) as raised,
        ):
            namespace.run_command([sys.executable, "-c", "import time; time.sleep(10)"])
        self.assertIs(raised.exception, primary)
        self.assertIn("owned process cleanup unconfirmed: RuntimeError", raised.exception.__notes__)
        self.assert_retained(raised.exception)

    def test_report_retains_known_status_and_defers_policy_removal(self):
        owned = self.directory / "namespace"
        owned.mkdir()
        report = self.directory / "report.json"
        with (
            mock.patch.object(namespace, "restriction", return_value="1"),
            mock.patch.object(namespace, "prepare"),
            mock.patch.object(namespace, "cleanup") as policy_cleanup,
            mock.patch.object(namespace.tempfile, "mkdtemp", return_value=str(owned)),
            mock.patch.object(namespace, "stop_owned", side_effect=self.refuse_confirmation),
        ):
            status = namespace.run([sys.executable, "-c", "raise SystemExit(37)"], report)
        record = json.loads(report.read_text())
        self.records.append(record)
        self.assertNotEqual(status, 0)
        self.assertEqual(record["command_returncode"], 37)
        self.assertEqual(record["unconfirmed_groups"], [self.children[-1].pid])
        self.assertIn("37", record["error"])
        self.assertIn("policy_removal_deferred", record)
        self.assertTrue((owned / "recovery.json").exists())
        policy_cleanup.assert_not_called()

    def test_confirmed_cleanup_preserves_success_and_failure_return_values(self):
        for status in (0, 37):
            with self.subTest(status=status):
                result = namespace.run_command(
                    [sys.executable, "-c", f"raise SystemExit({status})"]
                )
                self.assertEqual(result, status)
                self.assertEqual(namespace._unconfirmed_groups, set())
                self.assertFalse(execution.group_running(self.children[-1].pid))


if __name__ == "__main__":
    unittest.main()
