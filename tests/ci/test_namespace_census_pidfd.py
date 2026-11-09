"""Bounded child/fault helpers; no real Nix, AppArmor or kernel PID-reuse claim."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest assertions also execute under Python -O.
import contextlib
import errno
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
sys.path.insert(0, str(ROOT / "tests" / "organizations"))
import namespace_lifecycle_processes as processes  # noqa: E402 - fixed repository helper.

EXECUTABLE = str(Path("/proc/self/exe").readlink())
OBSERVATIONS: list[dict] = []
CHILD = """import sys,time
from pathlib import Path
ready, finish = map(Path, sys.argv[1:])
ready.write_text('ready')
deadline = time.monotonic() + 30
while not finish.exists() and time.monotonic() < deadline:
    time.sleep(.01)
"""


@contextlib.contextmanager
def child(directory: Path, **environment: str):
    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        ready, finish = Path(temporary) / "ready", Path(temporary) / "finish"
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter/code, no shell.
            [EXECUTABLE, "-c", CHILD, str(ready), str(finish)],
            cwd=directory,
            env={**os.environ, **environment},
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 3
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not ready.exists():
                message = "owned fixture child did not become ready"
                raise AssertionError(message)
            yield process, finish
        finally:
            finish.touch()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            absent = not Path("/proc", str(process.pid)).exists()
            OBSERVATIONS.append(
                {"pid": process.pid, "returncode": process.returncode, "reaped": absent}
            )
            if not absent:
                message = "owned fixture child was not reaped"
                raise AssertionError(message)


class NamespaceCensusPidfdTests(unittest.TestCase):
    @contextlib.contextmanager
    def census(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            census = processes.Census(
                {
                    "scratch": str(root / "scratch"),
                    "nonce": "a" * 32,
                    "outputs": {"probe": "/nix/store/probe", "payload": "/nix/store/payload"},
                    "caller_uid": os.getuid(),
                    "owner_starttime": int(processes.process_fields(os.getpid())[19]),
                    "nix_executable": EXECUTABLE,
                }
            )
            try:
                yield census
            finally:
                census.close()

    def assert_closed(self, descriptor):
        with self.assertRaises(OSError) as caught:
            os.fstat(descriptor)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def assert_actual_stop(self, kind, signum):
        with self.census() as census:
            environment = (
                {"AEGAEON_NAMESPACE_LIFECYCLE_CASE": "a" * 32}
                if kind == "client"
                else {"out": "/nix/store/payload", "AEGAEON_NAMESPACE_LIFECYCLE_NONCE": "a" * 32}
            )
            with child(census.scratch, **environment) as (owned, _):
                row = census.inspect(owned.pid, census.directories())
                self.assertIsNotNone(row)
                self.assertEqual(row["kind"], kind)
                events, descriptors = [], []
                real_open, real_inspect, real_send = (
                    os.pidfd_open,
                    census.inspect,
                    signal.pidfd_send_signal,
                )

                def opened(pid):
                    self.assertEqual(pid, owned.pid)
                    descriptor = real_open(pid)
                    descriptors.append(descriptor)
                    events.append("open")
                    return descriptor

                def inspected(pid, directories):
                    self.assertEqual(events, ["open"])
                    os.fstat(descriptors[0])
                    events.append("inspect")
                    return real_inspect(pid, directories)

                def sent(descriptor, actual_signal):
                    self.assertEqual(events, ["open", "inspect"])
                    self.assertEqual((descriptor, actual_signal), (descriptors[0], signum))
                    events.append("signal")
                    return real_send(descriptor, actual_signal)

                with (
                    mock.patch.object(census, "snapshot", return_value={"rows": [row]}),
                    mock.patch.object(processes.os, "pidfd_open", side_effect=opened),
                    mock.patch.object(census, "inspect", side_effect=inspected),
                    mock.patch.object(processes.signal, "pidfd_send_signal", side_effect=sent),
                    mock.patch.object(
                        processes.os, "kill", side_effect=AssertionError("numeric signal forbidden")
                    ),
                ):
                    actions = census.stop(signum)
                self.assertEqual(actions, [{"identity": row, "signal": signum}])
                self.assertEqual(events, ["open", "inspect", "signal"])
                self.assert_closed(descriptors[0])
                self.assertEqual(owned.wait(timeout=3), -signum)

    def test_actual_client_and_payload_signals_use_pidfd_after_reinspection(self):
        for kind in ("client", "payload"):
            for signum in (signal.SIGTERM, signal.SIGKILL):
                with self.subTest(kind=kind, signum=signum):
                    self.assert_actual_stop(kind, signum)

    def test_exited_task_after_reinspection_cannot_fall_back_to_numeric_pid(self):
        with (
            self.census() as census,
            child(census.scratch, AEGAEON_NAMESPACE_LIFECYCLE_CASE="a" * 32) as (owned, finish),
        ):
            row = census.inspect(owned.pid, census.directories())
            self.assertIsNotNone(row)
            descriptors = []
            real_open, real_inspect = os.pidfd_open, census.inspect

            def opened(pid):
                descriptor = real_open(pid)
                descriptors.append(descriptor)
                return descriptor

            def exited(pid, directories):
                actual = real_inspect(pid, directories)
                finish.touch()
                self.assertEqual(owned.wait(timeout=3), 0)
                return actual

            with (
                mock.patch.object(census, "snapshot", return_value={"rows": [row]}),
                mock.patch.object(processes.os, "pidfd_open", side_effect=opened),
                mock.patch.object(census, "inspect", side_effect=exited),
                mock.patch.object(
                    processes.os, "kill", side_effect=AssertionError("numeric signal forbidden")
                ),
            ):
                self.assertEqual(census.stop(signal.SIGTERM), [])
            self.assert_closed(descriptors[0])

    def test_open_failures_refuse_without_inspection_or_numeric_fallback(self):
        with self.census() as census:
            row = {"pid": 123, "kind": "client"}
            for error in (
                ProcessLookupError(),
                PermissionError("denied"),
                OSError(errno.ENOSYS, "unsupported"),
            ):
                with (
                    self.subTest(error=type(error).__name__),
                    mock.patch.object(census, "snapshot", return_value={"rows": [row]}),
                    mock.patch.object(processes.os, "pidfd_open", side_effect=error),
                    mock.patch.object(census, "inspect") as inspect,
                    mock.patch.object(processes.signal, "pidfd_send_signal") as send,
                    mock.patch.object(processes.os, "kill") as numeric,
                ):
                    if isinstance(error, ProcessLookupError):
                        self.assertEqual(census.stop(signal.SIGTERM), [])
                    else:
                        with self.assertRaises(type(error)):
                            census.stop(signal.SIGTERM)
                    inspect.assert_not_called()
                    send.assert_not_called()
                    numeric.assert_not_called()

    def test_changed_or_missing_reinspection_closes_descriptor_without_signal(self):
        with self.census() as census:
            row = {"pid": 123, "kind": "client", "starttime": "1"}
            for actual in (None, {**row, "starttime": "2"}):
                descriptor = os.open(os.devnull, os.O_RDONLY)
                try:
                    with (
                        self.subTest(actual=actual),
                        mock.patch.object(census, "snapshot", return_value={"rows": [row]}),
                        mock.patch.object(
                            processes.os, "pidfd_open", return_value=descriptor
                        ) as opened,
                        mock.patch.object(census, "inspect", return_value=actual),
                        mock.patch.object(processes.signal, "pidfd_send_signal") as send,
                    ):
                        self.assertEqual(census.stop(signal.SIGTERM), [])
                    opened.assert_called_once_with(row["pid"])
                    send.assert_not_called()
                    self.assert_closed(descriptor)
                finally:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def test_permission_and_inventory_errors_after_open_close_before_propagating(self):
        with self.census() as census:
            row = {"pid": 123, "kind": "client"}
            for target, error in (
                ("inspect", PermissionError("environment denied")),
                ("directories", ValueError("inventory exceeds its bound")),
                ("directories", FileNotFoundError("private root removed")),
            ):
                descriptor = os.open(os.devnull, os.O_RDONLY)
                try:
                    with (
                        self.subTest(target=target, error=type(error).__name__),
                        mock.patch.object(census, "snapshot", return_value={"rows": [row]}),
                        mock.patch.object(processes.os, "pidfd_open", return_value=descriptor),
                        mock.patch.object(census, target, side_effect=error),
                        mock.patch.object(processes.signal, "pidfd_send_signal") as send,
                        self.assertRaises(type(error)),
                    ):
                        census.stop(signal.SIGTERM)
                    send.assert_not_called()
                    self.assert_closed(descriptor)
                finally:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def test_send_failure_closes_descriptor_and_permission_is_not_absence(self):
        with self.census() as census:
            row = {"pid": 123, "kind": "client"}
            for error in (ProcessLookupError(), PermissionError("signal denied")):
                descriptor = os.open(os.devnull, os.O_RDONLY)
                try:
                    with (
                        self.subTest(error=type(error).__name__),
                        mock.patch.object(census, "snapshot", return_value={"rows": [row]}),
                        mock.patch.object(processes.os, "pidfd_open", return_value=descriptor),
                        mock.patch.object(census, "inspect", return_value=row),
                        mock.patch.object(processes.signal, "pidfd_send_signal", side_effect=error),
                        mock.patch.object(processes.os, "kill") as numeric,
                    ):
                        if isinstance(error, ProcessLookupError):
                            self.assertEqual(census.stop(signal.SIGTERM), [])
                        else:
                            with self.assertRaises(PermissionError):
                                census.stop(signal.SIGTERM)
                    numeric.assert_not_called()
                    self.assert_closed(descriptor)
                finally:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def test_unsupported_signal_does_not_open_pidfd_or_scan_processes(self):
        with self.census() as census:
            with (
                mock.patch.object(census, "snapshot") as snapshot,
                mock.patch.object(processes.os, "pidfd_open") as opened,
                self.assertRaisesRegex(ValueError, "unsupported"),
            ):
                census.stop(signal.SIGINT)
            snapshot.assert_not_called()
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
