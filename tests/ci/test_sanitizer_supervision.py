"""Bound command capture even when an owned test pipe holder leaves its group."""
# ruff: noqa: PT009, PT027 - unittest assertions remain active with Python -O

from __future__ import annotations

import contextlib
import json
import os
import runpy
import select
import signal
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


class ProcessGroupScanTests(unittest.TestCase):
    def setUp(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        self.inspect = namespace["group_alive"]
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.scandir = os.scandir
        # These /proc fixtures represent groups whose kernel probe succeeded.
        self.probe = self.enterContext(patch.object(os, "killpg"))

    def stat(self, name, state, group):
        path = self.root / name
        path.mkdir(exist_ok=True)
        # The comm field can itself contain spaces and closing parentheses.
        (path / "stat").write_text(f"{name} (worker ) name) {state} 1 {group} 0\n")

    def inspect_fixture(self, group):
        with patch.object(os, "scandir", return_value=self.scandir(self.root)) as scan:
            result = self.inspect(group)
        scan.assert_called_once_with("/proc")
        return result

    def test_group_membership_and_exited_states(self):
        self.stat("100", "Z", 71)
        self.stat("101", "X", 71)
        self.stat("102", "S", 72)
        (self.root / "self").mkdir()  # Non-PID entries need no stat file.
        self.assertFalse(self.inspect_fixture(71))
        self.assertTrue(self.inspect_fixture(72))
        self.stat("103", "S", 71)
        self.assertTrue(self.inspect_fixture(71))

    def test_every_scan_observes_exit_and_new_members(self):
        self.stat("100", "S", 71)
        self.assertTrue(self.inspect_fixture(71))
        self.stat("100", "Z", 71)
        self.assertFalse(self.inspect_fixture(71))
        self.stat("101", "R", 71)
        self.assertTrue(self.inspect_fixture(71))

    def test_disappearing_processes_are_ignored(self):
        (self.root / "100").mkdir()
        self.assertFalse(self.inspect_fixture(71))
        with patch.dict(self.inspect.__globals__, open=Mock(side_effect=ProcessLookupError)):
            self.assertFalse(self.inspect_fixture(71))

    def test_unreadable_or_malformed_stat_is_not_absence(self):
        self.stat("100", "S", 71)
        with (
            patch.dict(self.inspect.__globals__, open=Mock(side_effect=PermissionError)),
            self.assertRaises(PermissionError),
        ):
            self.inspect_fixture(71)
        for content in ("not a stat record", "100 (worker) S 1 invalid 0"):
            with self.subTest(content=content):
                (self.root / "100/stat").write_text(content)
                with self.assertRaises((IndexError, ValueError)):
                    self.inspect_fixture(71)

    def test_directory_scan_failure_is_not_absence(self):
        with (
            patch.object(os, "scandir", side_effect=PermissionError),
            self.assertRaises(PermissionError),
        ):
            self.inspect(71)

    def test_partial_directory_failure_precedes_member_inspection(self):
        self.stat("100", "S", 71)
        with self.scandir(self.root) as scan:
            first = next(scan)

        def interrupted_scan():
            yield first
            message = "controlled directory read failure"
            raise OSError(message)

        read = Mock()
        with (
            patch.object(os, "scandir", return_value=contextlib.nullcontext(interrupted_scan())),
            patch.dict(self.inspect.__globals__, open=read),
            self.assertRaises(OSError),
        ):
            self.inspect(71)
        read.assert_not_called()

    def test_scan_iterator_closes_on_early_return_and_error(self):
        self.stat("100", "S", 71)
        for content, error in (("100 (worker) R 1 71 0", False), ("malformed", True)):
            with self.subTest(error=error):
                (self.root / "100/stat").write_text(content)
                entries = self.scandir(self.root)
                with patch.object(os, "scandir", return_value=entries):
                    if error:
                        with self.assertRaises(IndexError):
                            self.inspect(71)
                    else:
                        self.assertTrue(self.inspect(71))
                self.assertEqual(list(entries), [])


class ProcessGroupProbeTests(unittest.TestCase):
    def setUp(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        self.inspect = namespace["group_alive"]

    def test_absent_group_avoids_proc_reads(self):
        with (
            patch.object(os, "killpg", side_effect=ProcessLookupError) as probe,
            patch.object(os, "scandir") as scan,
        ):
            self.assertFalse(self.inspect(1234))
        probe.assert_called_once_with(1234, 0)
        scan.assert_not_called()

    def test_probe_errors_are_not_absence(self):
        for error in (PermissionError, InterruptedError, OSError):
            with (
                self.subTest(error=error),
                patch.object(os, "killpg", side_effect=error),
                patch.object(os, "scandir") as scan,
                self.assertRaises(error),
            ):
                self.inspect(1234)
            scan.assert_not_called()

    def test_each_call_rechecks_the_kernel(self):
        with (
            patch.object(os, "killpg", side_effect=[ProcessLookupError, None]) as probe,
            patch.object(os, "scandir", side_effect=PermissionError) as scan,
        ):
            self.assertFalse(self.inspect(1234))
            with self.assertRaises(PermissionError):
                self.inspect(1234)
        self.assertEqual(probe.call_count, 2)
        scan.assert_called_once_with("/proc")


def stop_pipe_holder(pid_path, finished, watchdog_expired, cleanup_errors):
    """Keep a pidfd until the independent test watchdog or normal cleanup."""
    try:
        while not pid_path.exists():
            if finished.wait(0.01):
                return
        descriptor = os.pidfd_open(int(pid_path.read_text()))
        try:
            if not finished.wait(2):
                watchdog_expired.append(True)
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            if not select.select([descriptor], [], [], 2)[0]:
                cleanup_errors.append("owned pipe holder did not stop")
        finally:
            os.close(descriptor)
    except Exception as error:  # noqa: BLE001 - propagate cleanup errors to test
        cleanup_errors.append(error)


@unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux owned-pid cleanup required")
class SupervisionDeadlineTests(unittest.TestCase):
    def test_escaped_pipe_holder_cannot_prolong_deadline_or_claim_completion(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_path = root / "holder.pid"
            finished = threading.Event()
            watchdog_expired = []
            cleanup_errors = []

            guard = threading.Thread(
                target=stop_pipe_holder,
                args=(pid_path, finished, watchdog_expired, cleanup_errors),
                daemon=True,
            )
            guard.start()
            # Only this harmless fixture creates the escaped session. Its pidfd
            # stays owned by the watchdog until cleanup, even after leader exit.
            child = (
                "import pathlib,subprocess,sys\n"
                "holder=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
                "start_new_session=True)\n"
                "pathlib.Path(sys.argv[1]).write_text(str(holder.pid))\n"
                "print('retained command output',flush=True)\n"
            )
            summary = {"commands": []}
            supervisor = namespace["Supervisor"](root, summary, 0.01)
            try:
                with self.assertRaises(namespace["Failure"]) as caught:
                    supervisor.command(
                        [sys.executable, "-c", child, str(pid_path)],
                        os.environ.copy(),
                        0.2,
                        "escaped-pipe",
                    )
                self.assertEqual(caught.exception.status, 124)
            finally:
                finished.set()
                guard.join(timeout=3)
            self.assertFalse(guard.is_alive(), "owned cleanup did not finish")
            self.assertEqual(cleanup_errors, [])
            self.assertEqual(watchdog_expired, [], "capture waited for external pipe EOF")
            saved = json.loads((root / "run-summary.json").read_text())
            command = saved["commands"][0]
            self.assertTrue(command["timed_out"])
            self.assertEqual(command["status"], "failed")
            self.assertEqual(command["exit_code"], 0)
            self.assertEqual(Path(command["stdout"]).read_bytes(), b"retained command output\n")


if __name__ == "__main__":
    unittest.main()
