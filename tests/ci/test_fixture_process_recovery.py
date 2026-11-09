"""Actual Python-only controller timeouts; no PostgreSQL or native suppliers."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - dependency-free unittest assertions survive Python -O.
# ruff: noqa: EM101, TRY003 - fixed test rejection messages.
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

import fixture_processes as fixture
import test_database_cleanup_cancellation as cleanup
import test_database_finalizer_entry as finalizer
import test_database_package_cancellation as package
from fixture_processes import run_fixture

ROOT = Path(__file__).resolve().parents[2]
PAUSE = (
    "(directory/'forced-timeout-ready').write_text('ready'); "
    "print('fixture partial stdout', flush=True); "
    "print('fixture partial stderr', file=sys.stderr, flush=True); "
    "time.sleep(60); "
)


def command_for(directory, shape):
    """Delay only a test controller after real children exist, before its cleanup."""
    source, old, new, extra = {
        "cleanup": (
            cleanup.CONTROLLER,
            "execution.stop_process_group(leader, grace=2)",
            PAUSE + "execution.stop_process_group(leader, grace=2)",
            ["sigterm", "execution"],
        ),
        "package": (
            package.CONTROLLER,
            "process.send_signal(signal.SIGTERM)",
            PAUSE + "process.send_signal(signal.SIGTERM)",
            [],
        ),
        "finalizer": (
            finalizer.CONTROLLER,
            "raise ValueError('controlled output failure')",
            PAUSE + "raise ValueError('controlled output failure')",
            ["build"],
        ),
    }[shape]
    if source.count(old) != 1:
        raise ValueError("test controller fault boundary changed")
    path = directory / "controller.py"
    path.write_text("import time\n" + source.replace(old, new))
    return [sys.executable, str(path), str(ROOT), str(directory), *extra]


class FixtureProcessRecoveryTests(unittest.TestCase):
    def scenario(self, shape):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            command = command_for(directory, shape)
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                run_fixture(
                    command,
                    timeout=5,
                    record_directory=directory / "recovery",
                    force_timeout_after_ready=directory / "forced-timeout-ready",
                )
            error = caught.exception
            record = error.fixture_recovery
            self.assertTrue(record["forced_timeout_ready"], record)
            self.assertTrue(record["timed_out"] and record["cleanup_confirmed"], record)
            self.assertEqual(record["controller_returncode"], -9, record)
            self.assertTrue(record["live_descendants_before_recovery"], record)
            self.assertIn("fixture partial stdout", error.stdout)
            self.assertIn("fixture partial stderr", error.stderr)
            self.assertEqual(record["remaining_children"], [], record)
            identities = [record["controller_identity"], *record["owned_children"]]
            for row in identities:
                self.assertFalse(Path(f"/proc/{row['pid']}").exists(), row)
            self.assertFalse(Path(f"/proc/{record['supervisor']}").exists(), record)
            saved = json.loads((directory / "recovery/result.json").read_text())
            self.assertEqual(saved, record)

    def test_cleanup_controller_timeout_reaps_separate_supplier(self):
        self.scenario("cleanup")

    def test_package_controller_timeout_reaps_runner_and_native_standin(self):
        self.scenario("package")

    def test_finalizer_controller_timeout_reaps_held_work(self):
        self.scenario("finalizer")

    def test_nonzero_status_and_streams_survive_orphan_recovery(self):
        code = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
            "start_new_session=True); "
            "print('known stdout',flush=True); print('known stderr',file=sys.stderr,flush=True); "
            "raise SystemExit(37)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                run_fixture(
                    [sys.executable, "-c", code],
                    timeout=5,
                    record_directory=Path(temporary) / "recovery",
                )
            error = caught.exception
            record = error.fixture_recovery
            self.assertEqual(error.returncode, 37)
            self.assertIn("known stdout", error.stdout)
            self.assertIn("known stderr", error.stderr)
            self.assertTrue(record["cleanup_confirmed"])
            self.assertTrue(record["live_descendants_before_recovery"])
            self.assertEqual(record["controller_returncode"], 37)
            self.observations = record
            for row in [record["controller_identity"], *record["owned_children"]]:
                self.assertFalse(Path(f"/proc/{row['pid']}").exists(), row)
            with self.assertRaises(RuntimeError) as bounded:
                run_fixture(
                    [
                        sys.executable,
                        "-c",
                        (
                            f"import sys,time; sys.stdout.write('x'*{fixture.MAX_OUTPUT + 1}); "
                            "sys.stdout.flush(); time.sleep(60)"
                        ),
                    ],
                    timeout=5,
                    record_directory=Path(temporary) / "output-bound",
                )
            failed = bounded.exception.fixture_recovery
            self.assertIsNone(failed["observed_controller_returncode"])
            self.assertEqual(failed["controller_returncode"], -9)
            self.assertTrue(failed["cleanup_confirmed"])
            self.assertIn("fixture output exceeded", str(bounded.exception))
            self.assertFalse(Path(f"/proc/{failed['controller_identity']['pid']}").exists())
            self.observations = {"known_nonzero": record, "cleanup_generated_status": failed}

    def test_pidfd_exit_race_refuses_unknown_and_permission_errors(self):
        observed = []
        for duration in (0.05, 60):
            child = subprocess.Popen(  # noqa: S603 - explicit owned Python child.
                [sys.executable, "-c", f"import time; time.sleep({duration})"]
            )
            descriptor = os.pidfd_open(child.pid)
            try:
                if duration < 1:
                    self.assertEqual(child.wait(timeout=3), 0)
                    self.assertFalse(fixture.signal_owned(descriptor, signal.SIGKILL))
                    observed.append({"pid": child.pid, "exited_pidfd_no_signal": True})
                else:
                    for failure in (
                        ProcessLookupError("unknown live fd"),
                        PermissionError("denied"),
                    ):
                        with (
                            mock.patch.object(
                                fixture.signal, "pidfd_send_signal", side_effect=failure
                            ),
                            self.assertRaises(type(failure)) as caught,
                        ):
                            fixture.signal_owned(descriptor, signal.SIGKILL)
                        self.assertIs(caught.exception, failure)
                    observed.append({"pid": child.pid, "unknown_and_permission_refused": True})
            finally:
                if child.poll() is None:
                    fixture.signal_owned(descriptor, signal.SIGKILL)
                child.wait(timeout=3)
                os.close(descriptor)
            self.assertFalse(Path(f"/proc/{child.pid}").exists())
        self.observations = observed

    def test_parent_interruption_waits_for_cooperative_supervisor_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ready = directory / "ready"
            code = (
                "import subprocess,sys,time; from pathlib import Path; "
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
                "start_new_session=True); "
                "Path(sys.argv[1]).write_text('ready'); time.sleep(60)"
            )
            primary = KeyboardInterrupt("controlled parent interruption")
            original_wait = subprocess.Popen.wait
            injected = False

            def wait(process, *args, **kwargs):
                nonlocal injected
                if not injected:
                    injected = True
                    until = time.monotonic() + 3
                    while not ready.exists():
                        if process.poll() is not None or time.monotonic() >= until:
                            raise RuntimeError("interruption fixture not ready")
                        time.sleep(0.01)
                    raise primary
                return original_wait(process, *args, **kwargs)

            with (
                mock.patch.object(subprocess.Popen, "wait", wait),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                run_fixture(
                    [sys.executable, "-c", code, str(ready)],
                    timeout=5,
                    record_directory=directory / "recovery",
                )
            self.assertIs(caught.exception, primary)
            record = primary.fixture_recovery
            self.assertTrue(record["cleanup_confirmed"], record)
            self.assertTrue(any("evidence" in note for note in primary.__notes__))
            self.observations = record
            for row in [record["controller_identity"], *record["owned_children"]]:
                self.assertFalse(Path(f"/proc/{row['pid']}").exists(), row)

    def test_parent_pin_failure_retains_error_and_waits_without_numeric_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            primary = PermissionError("controlled parent pidfd refusal")
            with (
                mock.patch.object(fixture.os, "pidfd_open", side_effect=primary),
                mock.patch.object(fixture.signal, "pidfd_send_signal") as send,
                self.assertRaises(PermissionError) as caught,
            ):
                run_fixture(
                    [sys.executable, "-c", "print('still owned')"],
                    timeout=3,
                    record_directory=Path(temporary) / "recovery",
                )
            self.assertIs(caught.exception, primary)
            send.assert_not_called()
            record = primary.fixture_recovery
            self.assertTrue(record["cleanup_confirmed"], record)
            self.assertEqual(record["controller_returncode"], 0)
            self.assertTrue(any("pin failed" in note for note in primary.__notes__))
            self.assertFalse(Path(f"/proc/{record['supervisor']}").exists())
            self.assertFalse(Path(f"/proc/{record['controller_identity']['pid']}").exists())
            self.observations = record


if __name__ == "__main__":
    unittest.main()
