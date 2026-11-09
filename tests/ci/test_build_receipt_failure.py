"""Observed command failures survive receipt and output publication faults."""

from __future__ import annotations

# ruff: noqa: PT009 - unittest owns and independently reclaims actual children.
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts/ci"), str(ROOT / "scripts/validation")]
import build_observations as build  # noqa: E402
import database_execution as execution  # noqa: E402


class BuildReceiptFailureTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.children = []
        self.records = []
        self.real_popen = subprocess.Popen
        self.addCleanup(self.recover)

    def recover(self):
        for child in self.children:
            execution.stop_process_group(child, grace=0.1)
            if child.stderr is not None:
                child.stderr.close()

    def scenario(self, fault="publication", status=37):  # noqa: C901, PLR0915 - one bounded actual-child observation.
        directory = self.directory / str(len(self.records))
        directory.mkdir()
        ready = directory / "ready"
        script = directory / "child.py"
        script.write_text(
            "import os,sys,time\nfrom pathlib import Path\n"
            "os.write(2,b'command failure explanation\\n')\n"
            f"Path({str(ready)!r}).write_text('ready')\n"
            + ("time.sleep(10)\n" if fault in ("timeout", "cancel") else f"sys.exit({status})\n")
        )
        command = [sys.executable, str(script)]
        injected = OSError(f"injected {fault} failure")
        timeout = subprocess.TimeoutExpired(command, 0.1)
        original = []
        published = []
        registered = []
        stream = io.BytesIO()
        real_update, real_observe, real_check = (
            build.cleanup_receipts.update,
            build.observe_process,
            build.check_cancellation,
        )

        def spawn(*args, **kwargs):
            child = self.real_popen(*args, **kwargs)
            self.children.append(child)
            if fault in ("timeout", "cancel"):
                until = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < until:
                    time.sleep(0.005)
                self.assertTrue(ready.exists())
            else:
                self.assertEqual(child.wait(timeout=3), status)
            return child

        def update(receipt, **changes):
            if fault == "registration" and "group" in changes:
                raise injected
            if changes.get("confirmed") and fault in ("publication", "timeout", "cancel"):
                published.append(False)
                raise injected
            real_update(receipt, **changes)
            if "group" in changes:
                registered.append(True)
            if changes.get("confirmed"):
                published.append(True)

        def check():
            if registered and not original:
                if fault == "timeout":
                    original.append(timeout)
                    raise timeout
                if fault == "cancel":
                    os.kill(os.getpid(), signal.SIGTERM)
                    try:
                        real_check()
                    except SystemExit as error:
                        original.append(error)
                        raise
            real_check()

        def observe(command, forward, *, status_observed=None):
            def callback(value):
                if status_observed is not None:
                    status_observed(value)
                if fault == "callback" or (
                    fault == "final-callback" and self.children[-1].stderr.closed
                ):
                    raise injected

            return real_observe(command, forward, status_observed=callback)

        def forward(chunk):
            if fault == "forward":
                raise injected
            return stream.write(chunk)

        receipts, trace = directory / "receipts", directory / "trace.jsonl"
        error = None
        with (
            build.cleanup_receipts.initialize(receipts, f"aegaeon-userns-{len(self.records):032x}"),
            mock.patch.dict(os.environ, {build.cleanup_receipts.ENVIRONMENT: str(receipts)}),
            mock.patch.object(build.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(build.cleanup_receipts, "update", side_effect=update),
            mock.patch.object(build, "check_cancellation", side_effect=check),
            mock.patch.object(build, "observe_process", side_effect=observe),
            mock.patch.object(
                build.sys,
                "stderr",
                SimpleNamespace(buffer=SimpleNamespace(write=forward, flush=stream.flush)),
            ),
        ):
            try:
                build.run_observed(command, trace)
            except BaseException as failure:  # noqa: BLE001 - preserve the actual outcome before recovery.
                error = failure
        child = self.children[-1]
        rows = [json.loads(line) for line in trace.read_text().splitlines()]
        receipt = [
            json.loads(path.read_text())
            for path in receipts.glob("*.json")
            if path.name != "owner.json"
        ]
        record = {
            "fault": fault,
            "status": status,
            "pid": child.pid,
            "error": type(error).__name__,
            "returncode": getattr(error, "returncode", None),
            "cause": type(error.__cause__).__name__ if error else None,
            "notes": getattr(error, "__notes__", []),
            "same_original": bool(original) and error is original[0],
            "source_pipe_closed": child.stderr.closed,
            "source_group_stopped": not execution.group_running(child.pid),
            "receipt": receipt,
            "publication_outcomes": published,
            "forwarded": stream.getvalue().decode(),
            "trace": rows,
            "captured": getattr(error, "observed_stderr", b"").decode(),
        }
        self.records.append(record)
        self.assertIsNotNone(error, record)
        self.assertTrue(record["source_group_stopped"], record)
        self.assertEqual(len(receipt), 1, record)
        self.assertEqual(
            receipt[0]["confirmed"], fault in ("callback", "final-callback", "forward"), record
        )
        self.assertEqual(
            rows[-1]["returncode"],
            None if fault in ("registration", "timeout", "cancel") else status,
            record,
        )
        return error, injected, record

    def test_known_failure_survives_confirmed_receipt_publication_error(self):
        error, injected, record = self.scenario()
        self.assertIsInstance(error, subprocess.CalledProcessError, record)
        self.assertEqual(error.returncode, 37, record)
        self.assertIs(error.__cause__, injected, record)
        self.assertEqual(error.stderr, b"command failure explanation\n", record)
        self.assertEqual(record["forwarded"], "command failure explanation\n", record)
        self.assertEqual(record["trace"][-1]["returncode"], 37, record)
        self.assertTrue(record["source_pipe_closed"], record)

    def test_zero_exit_does_not_mask_receipt_publication_error(self):
        error, injected, record = self.scenario(status=0)
        self.assertIs(error, injected, record)
        self.assertEqual(record["captured"], "command failure explanation\n", record)
        self.assertTrue(record["source_pipe_closed"], record)

    def test_known_failure_survives_status_callback_errors(self):
        for fault in ("callback", "final-callback"):
            with self.subTest(fault=fault):
                error, injected, record = self.scenario(fault)
                self.assertIsInstance(error, subprocess.CalledProcessError, record)
                self.assertEqual(error.returncode, 37, record)
                self.assertIs(error.__cause__, injected, record)
                self.assertEqual(record["forwarded"], "command failure explanation\n", record)
                self.assertTrue(record["source_pipe_closed"], record)

    def test_known_failure_survives_forwarding_error_without_resending(self):
        error, injected, record = self.scenario("forward")
        self.assertIsInstance(error, subprocess.CalledProcessError, record)
        self.assertEqual(error.returncode, 37, record)
        self.assertIs(error.__cause__, injected, record)
        self.assertEqual(error.stderr, b"command failure explanation\n", record)
        self.assertEqual(error.stderr_recovery["attempted_bytes_not_resent"], len(error.stderr))
        self.assertEqual(record["forwarded"], "", record)
        self.assertTrue(record["source_pipe_closed"], record)

    def test_earlier_cancellation_and_timeout_survive_publication_error(self):
        # Timeout is an explicit fault at a checkpoint; cancellation is real SIGTERM.
        for fault in ("timeout", "cancel"):
            with self.subTest(fault=fault):
                error, _, record = self.scenario(fault)
                self.assertTrue(record["same_original"], record)
                self.assertIsInstance(
                    error, subprocess.TimeoutExpired if fault == "timeout" else SystemExit
                )
                if fault == "cancel":
                    self.assertEqual(error.code, 143)
                self.assertIsNone(error.__cause__, record)
                self.assertEqual(record["captured"], "command failure explanation\n", record)
                self.assertIn("observed process cleanup unconfirmed: OSError", record["notes"])
                self.assertTrue(record["source_pipe_closed"], record)

    def test_registration_failure_closes_pipe_and_keeps_failed_receipt(self):
        error, injected, record = self.scenario("registration")
        self.assertIs(error, injected, record)
        self.assertIsNone(record["receipt"][0]["group"], record)
        self.assertTrue(record["source_pipe_closed"], record)
        self.assertEqual(record["captured"], "command failure explanation\n", record)


if __name__ == "__main__":
    unittest.main()
