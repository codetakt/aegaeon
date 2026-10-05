"""Bound command capture even when an owned test pipe holder leaves its group."""
# ruff: noqa: PT009, PT027 - unittest assertions remain active with Python -O

from __future__ import annotations

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

ROOT = Path(__file__).resolve().parents[2]


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
