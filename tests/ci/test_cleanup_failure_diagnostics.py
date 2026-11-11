"""Real command diagnostics survive a simulated group-confirmation failure."""

from __future__ import annotations

# ruff: noqa: PT009 - unittest and fixed, independently reclaimed children.
import importlib.util
import json
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
import build_observations as build  # noqa: E402
import database_execution as execution  # noqa: E402
import with_organization_userns as namespace  # noqa: E402


class CleanupFailureDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.children = []
        self.records = []
        self.real_popen = subprocess.Popen
        self.addCleanup(self.recover)
        spec = importlib.util.spec_from_file_location(
            "diagnostic_current_process", ROOT / "tests/organizations/current_process.py"
        )
        self.current = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.current)
        previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        self.addCleanup(lambda: [signal.signal(s, handler) for s, handler in previous.items()])
        self.enterContext(mock.patch.object(namespace, "_cancellation", None))
        self.enterContext(mock.patch.object(namespace, "_cleaning", False))
        self.enterContext(mock.patch.object(namespace, "_unconfirmed_groups", set()))

    def recover(self):
        for child in self.children:
            execution.stop_process_group(child, grace=0.1)

    def capture_case(  # noqa: C901, PLR0915 - one owned-child diagnostic observation.
        self, owner, code, *, interruption=None, private=False, capture_failure=False
    ):
        module = self.current if owner == "current" else namespace
        if owner == "current":
            module.install_cancellation()
        else:
            signal.signal(signal.SIGTERM, module.interrupted)
        ready = self.directory / "ready"
        ready.unlink(missing_ok=True)
        script = (
            "import os,sys,time; from pathlib import Path; "
            "print('original stdout',flush=True); "
            "print('original stderr',file=sys.stderr,flush=True); "
            f"Path({str(ready)!r}).write_text('ready'); "
            + ("time.sleep(10)" if interruption == "timeout" else f"sys.exit({code})")
        )
        script_path = self.directory / "capture-child.py"
        script_path.write_text(script)
        command = [sys.executable, str(script_path)]
        cleanup_error = TimeoutError("injected stop confirmation refusal")
        primary = None

        def spawn(*args, **kwargs):
            child = self.real_popen(*args, **kwargs)
            self.children.append(child)
            if interruption != "timeout":
                self.assertEqual(child.wait(timeout=3), code)
            else:
                until = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < until:
                    time.sleep(0.005)
                self.assertTrue(ready.exists())
            return child

        real_wait = module.wait_owned if owner == "current" else module.wait_command

        def wait(*args, **kwargs):
            nonlocal primary
            if interruption == "cancel":
                os.kill(os.getpid(), signal.SIGTERM)
                primary = module._cancellation
                module.check_cancellation()
            try:
                return real_wait(*args, **kwargs)
            except subprocess.TimeoutExpired as error:
                primary = error
                raise

        private_log = self.directory / "private.log" if private else None
        error = None
        real_pread, reads = os.pread, []

        def pread(*args):
            reads.append(True)
            if capture_failure and len(reads) == 2:
                raise OSError("injected diagnostic read failure")  # noqa: EM101, TRY003
            return real_pread(*args)

        with (
            mock.patch.object(module.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(module, "stop_owned", side_effect=cleanup_error),
            mock.patch.object(module.os, "pread", side_effect=pread),
            mock.patch.object(
                module, "wait_owned" if owner == "current" else "wait_command", side_effect=wait
            ),
        ):
            try:
                if owner == "current":
                    module.run_owned(
                        command,
                        root=self.directory,
                        env=dict(os.environ),
                        timeout=0.2 if interruption == "timeout" else 3,
                        private_log=private_log,
                    )
                else:
                    module.execute(command, timeout=0.2 if interruption == "timeout" else 3)
            except BaseException as failure:  # noqa: BLE001 - record the actual failure before recovery.
                error = failure
        child = self.children[-1]
        registered = child.pid in module._unconfirmed_groups
        live_before_recovery = execution.group_running(child.pid)
        execution.stop_process_group(child, grace=0.1)
        result = getattr(error, "command_result", None)
        record = {
            "owner": owner,
            "code": code,
            "interruption": interruption,
            "pid": child.pid,
            "error": type(error).__name__,
            "message": str(error),
            "cause": type(error.__cause__).__name__ if error else None,
            "returncode": getattr(error, "returncode", None),
            "command_result": vars(result) if result is not None else None,
            "registered_before_recovery": registered,
            "live_before_recovery": live_before_recovery,
            "live_after_recovery": execution.group_running(child.pid),
            "primary_preserved": primary is not None and error is primary,
            "notes": getattr(error, "__notes__", []),
            "private_log": private_log.read_text() if private_log else None,
        }
        self.records.append(record)
        self.assertTrue(registered, record)
        self.assertFalse(record["live_after_recovery"], record)
        self.assertIsNotNone(error, record)
        return error, result, record

    def assert_captured_failure(self, owner, code):
        error, result, record = self.capture_case(owner, code)
        if code:
            self.assertIsInstance(error, subprocess.CalledProcessError, record)
            self.assertEqual(error.returncode, code, record)
            self.assertIsInstance(error.__cause__, TimeoutError, record)
        else:
            self.assertIsInstance(error, TimeoutError, record)
        self.assertIsNotNone(result, record)
        self.assertEqual(result.returncode, code, record)
        self.assertEqual(result.stdout, "original stdout\n", record)
        self.assertEqual(result.stderr, "original stderr\n", record)

    def test_current_nonzero_diagnostics_survive_unconfirmed_stop(self):
        self.assert_captured_failure("current", 37)

    def test_namespace_nonzero_diagnostics_survive_unconfirmed_stop(self):
        self.assert_captured_failure("namespace", 37)

    def test_successful_leader_does_not_mask_unconfirmed_stop(self):
        for owner in ("current", "namespace"):
            with self.subTest(owner=owner):
                self.assert_captured_failure(owner, 0)

    def test_original_timeout_and_cancellation_keep_partial_diagnostics(self):
        for owner in ("current", "namespace"):
            for interruption in ("timeout", "cancel"):
                with self.subTest(owner=owner, interruption=interruption):
                    _, result, record = self.capture_case(owner, 37, interruption=interruption)
                    self.assertTrue(record["primary_preserved"], record)
                    self.assertIsNotNone(result, record)
                    self.assertEqual(result.stdout, "original stdout\n", record)
                    self.assertEqual(result.stderr, "original stderr\n", record)
                    self.assertTrue(record["notes"], record)

    def test_private_log_stays_private_when_stop_is_unconfirmed(self):
        error, result, record = self.capture_case("current", 37, private=True)
        self.assertIsInstance(error, subprocess.CalledProcessError, record)
        self.assertEqual(record["private_log"], "original stdout\noriginal stderr\n", record)
        self.assertIsNotNone(result, record)
        self.assertIsNone(result.stdout, record)
        self.assertIsNone(result.stderr, record)
        self.assertNotIn("original stdout", str(error), record)

    def test_partial_capture_error_preserves_known_status_and_primary_failure(self):
        for owner in ("current", "namespace"):
            for interruption in (None, "cancel"):
                with self.subTest(owner=owner, interruption=interruption):
                    error, result, record = self.capture_case(
                        owner, 37, interruption=interruption, capture_failure=True
                    )
                    if interruption:
                        self.assertTrue(record["primary_preserved"], record)
                    else:
                        self.assertIsInstance(error, subprocess.CalledProcessError, record)
                    self.assertEqual(result.returncode, 37, record)
                    self.assertEqual(result.stdout, "original stdout\n", record)
                    self.assertIsNone(result.stderr, record)
                    self.assertIn("command diagnostic capture failed: OSError", record["notes"])

    def test_build_finish_preserves_known_status_when_stop_is_unconfirmed(self):  # noqa: PLR0915 - single child/receipt boundary.
        for code in (37, 0):
            with self.subTest(code=code):
                release = self.directory / "release"
                release.unlink(missing_ok=True)
                script = self.directory / "build-child.py"
                script.write_text(
                    "import sys,time\nfrom pathlib import Path\n"
                    "print('original build stderr',file=sys.stderr,flush=True)\n"
                    "until=time.monotonic()+3\n"
                    f"while not Path({str(release)!r}).exists() and time.monotonic()<until:\n"
                    " time.sleep(.005)\n"
                    f"sys.exit({code})\n"
                )
                command = [sys.executable, str(script)]
                real_read = os.read

                def spawn(*args, **kwargs):
                    child = self.real_popen(*args, **kwargs)
                    self.children.append(child)
                    return child

                def read(fd, size, real_read=real_read, release=release, code=code):
                    chunk = real_read(fd, size)
                    pipe = self.children[-1].stderr if self.children else None
                    if chunk and pipe is not None and not pipe.closed and fd == pipe.fileno():
                        release.write_text("release")
                        self.assertEqual(self.children[-1].wait(timeout=3), code)
                    return chunk

                trace = self.directory / f"build-{code}.jsonl"
                receipts = self.directory / f"receipts-{code}"
                with (
                    build.cleanup_receipts.initialize(receipts, f"aegaeon-userns-{code:032x}"),
                    mock.patch.dict(
                        os.environ, {build.cleanup_receipts.ENVIRONMENT: str(receipts)}
                    ),
                    mock.patch.object(build.subprocess, "Popen", side_effect=spawn),
                    mock.patch.object(build.os, "read", side_effect=read),
                    mock.patch.object(
                        build, "stop_process_group", side_effect=TimeoutError("unconfirmed group")
                    ),
                ):
                    try:
                        build.run_observed(command, trace)
                    except BaseException as failure:  # noqa: BLE001 - retain all actual failure kinds.
                        error = failure
                    else:
                        self.fail("unconfirmed cleanup succeeded")
                rows = [json.loads(line) for line in trace.read_text().splitlines()]
                record = {"code": code, "error": type(error).__name__, "trace": rows}
                registrations = [
                    json.loads(path.read_text())
                    for path in receipts.glob("*.json")
                    if path.name != "owner.json"
                ]
                record["receipts"] = registrations
                self.records.append(record)
                self.assertEqual(len(registrations), 1, record)
                self.assertFalse(registrations[0]["confirmed"], record)
                self.assertEqual(rows[-1]["returncode"], code, record)
                if code:
                    self.assertIsInstance(error, subprocess.CalledProcessError, record)
                    self.assertEqual(error.returncode, code, record)
                else:
                    self.assertIsInstance(error, TimeoutError, record)
                self.assertEqual(
                    "".join(row["text"] for row in rows if row["event"] == "output"),
                    "original build stderr\n",
                    record,
                )


if __name__ == "__main__":
    unittest.main()
