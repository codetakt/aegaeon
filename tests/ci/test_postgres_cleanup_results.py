"""Process/receipt fault regressions; these do not qualify real PostgreSQL cleanup."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest assertions remain active under Python -O.
import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "organizations"))
import check_current_runtime_postgres as subject  # noqa: E402 - fixed local helper.

PYTHON = str(Path("/proc/self/exe").readlink())
POPEN = subprocess.Popen


@contextlib.contextmanager
def child(code="import time; time.sleep(30)"):
    # Fixed interpreter/code, no shell.
    process = POPEN([PYTHON, "-c", code], start_new_session=True)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        if Path(f"/proc/{process.pid}").exists():
            message = "owned fixture child was not reaped"
            raise AssertionError(message)


def ownership_record(directory, process):
    """Synthetic PG role around a real owned Python PID; not a PostgreSQL claim."""
    pg = directory / "pg"
    pg.mkdir(exist_ok=True)
    executable = pg / "postgres"
    if not executable.exists():
        executable.symlink_to(PYTHON)
    data = directory / "data"
    data.mkdir(exist_ok=True)
    record = {
        **subject.postgres_ownership.definition(pg, data),
        "identity": subject.identity(process.pid),
    }
    return pg, data, record


@contextlib.contextmanager
def postmaster_standin(directory, *, ignore=False):
    """Real pidfd/signal/exit only; PostgreSQL executable/argv role is simulated."""
    code = f"""
import pathlib, signal, sys, time
root = pathlib.Path({str(directory)!r})
def stop(signum, frame):
    (root / 'signal').write_text(str(signum))
    if not {ignore!r}:
        (root / 'data/postmaster.pid').unlink()
        sys.exit(0)
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGQUIT, stop)
(root / 'ready').touch()
time.sleep(30)
"""
    with child(code) as process:
        deadline = time.monotonic() + 3
        while not (directory / "ready").exists():
            if time.monotonic() >= deadline or process.poll() is not None:
                message = "signal fixture did not become ready"
                raise AssertionError(message)
            time.sleep(0.01)
        pg, data, record = ownership_record(directory, process)
        (data / "postmaster.pid").write_text(f"{process.pid}\n{data}\n")
        yield process, pg, data, record


@contextlib.contextmanager
def owner_fixture(*, returncode=0):
    """Actual controller stand-ins; all PostgreSQL commands remain mocked."""
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        output = directory / "output"
        cases = []
        children = []
        args = types.SimpleNamespace(output=output, root=ROOT, postgres_bin=directory / "no-pg")

        def make_directory(*, prefix):
            path = directory / f"{prefix}{len(cases)}"
            path.mkdir()
            cases.append(path)
            return str(path)

        def spawn(_argv, **kwargs):
            (cases[-1] / "observation.json").write_text('{"fixture": "no PostgreSQL"}\n')
            # Fixed interpreter and integer exit status.
            process = POPEN([PYTHON, "-c", f"raise SystemExit({returncode})"], **kwargs)
            children.append(process)
            return process

        def stop(process, *, grace):
            del grace
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=3)

        execution = types.SimpleNamespace(
            cancellation_scope=contextlib.nullcontext,
            check_cancellation=lambda: None,
            stop_process_group=mock.Mock(side_effect=stop),
        )
        try:
            with (
                mock.patch.object(subject.tempfile, "mkdtemp", side_effect=make_directory),
                mock.patch.object(subject.subprocess, "Popen", side_effect=spawn),
                mock.patch.object(subject, "recover") as recover,
            ):
                yield args, execution, recover, cases, children
        finally:
            for process in children:
                stop(process, grace=0)
                if Path(f"/proc/{process.pid}").exists():
                    message = "owned controller stand-in was not reaped"
                    raise AssertionError(message)


class PostgresCleanupResultsTests(unittest.TestCase):
    def test_reaped_postmaster_after_identity_snapshot_is_absent(self):
        # A real exited child stands in only for the procfs identity boundary.
        with tempfile.TemporaryDirectory() as temporary, child() as process:
            directory = Path(temporary)
            pg, _data, record = ownership_record(directory, process)
            (directory / "postmaster-identity.json").write_text(json.dumps(record))
            process.terminate()
            stat_path = Path(f"/proc/{process.pid}/stat")
            deadline = time.monotonic() + 3
            while stat_path.read_text().rsplit(") ", 1)[1].split()[0] != "Z":
                if time.monotonic() >= deadline:
                    self.fail("fixture child did not exit")
                time.sleep(0.01)
            real_stat = Path.stat
            reaped = []

            def reap_after_uid(path, *args, **kwargs):
                value = real_stat(path, *args, **kwargs)
                if path == stat_path.parent and not reaped:
                    process.wait(timeout=3)
                    reaped.append(process.pid)
                return value

            with (
                mock.patch.object(Path, "stat", autospec=True, side_effect=reap_after_uid),
                mock.patch.object(subject, "command") as command,
            ):
                subject.recover(directory, pg, types.SimpleNamespace())
            command.assert_not_called()
            self.assertEqual(reaped, [process.pid])
            self.assertFalse(stat_path.exists())

    def test_live_or_reused_postmaster_is_not_cleanup_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary, child() as process:
            directory = Path(temporary)
            pg, _data, record = ownership_record(directory, process)
            owned = record["identity"]
            for reused in (False, True):
                with self.subTest(reused=reused):
                    saved = {**owned, "starttime": "0"} if reused else owned
                    (directory / "postmaster-identity.json").write_text(
                        json.dumps({**record, "identity": saved})
                    )
                    message = "PID was reused" if reused else "remains live"
                    with self.assertRaisesRegex(AssertionError, message):
                        subject.recover(directory, pg, types.SimpleNamespace())
                    self.assertIsNone(process.poll())

    def test_procfs_permission_error_is_not_absence(self):
        with (
            mock.patch.object(Path, "read_text", side_effect=PermissionError("procfs denied")),
            self.assertRaisesRegex(PermissionError, "procfs denied"),
        ):
            subject.identity(os.getpid())

    def test_controller_stop_failure_preserves_case_and_retains_suppliers(self):
        with owner_fixture() as (args, execution, recover, cases, _children):
            execution.stop_process_group.side_effect = TimeoutError("controller stop unconfirmed")
            with self.assertRaisesRegex(TimeoutError, "controller stop unconfirmed"):
                subject.owner(args, execution)
            recover.assert_not_called()
            result = json.loads((args.output / "cancel.json").read_text())
            self.assertFalse(result["passed"])
            self.assertFalse(result["owned_processes_stopped"])
            self.assertEqual(result["cleanup_stage"], "controller")
            self.assertEqual(result["recovery"]["directory"], str(cases[0]))
            self.assertEqual(
                result["recovery"]["work_identity"], str(cases[0] / "work-identity.json")
            )
            self.assertEqual(
                result["recovery"]["postmaster_identity"],
                str(cases[0] / "postmaster-identity.json"),
            )
            self.assertFalse((args.output / "result.json").exists())

    def test_recovery_failure_preserves_primary_work_error_and_case(self):
        for returncode in (0, 37):
            with (
                self.subTest(returncode=returncode),
                owner_fixture(returncode=returncode) as fixture,
            ):
                args, execution, recover, _cases, _children = fixture
                recover.side_effect = RuntimeError("supplier cleanup unconfirmed")
                expected = RuntimeError if returncode == 0 else AssertionError
                with self.assertRaises(expected) as caught:
                    subject.owner(args, execution)
                execution.stop_process_group.assert_called_once()
                recover.assert_called_once()
                result = json.loads((args.output / "cancel.json").read_text())
                self.assertFalse(result["passed"])
                self.assertFalse(result["owned_processes_stopped"])
                self.assertEqual(
                    result["cleanup_error"], "RuntimeError: supplier cleanup unconfirmed"
                )
                self.assertEqual(result["cleanup_stage"], "suppliers")
                if returncode == 37:
                    self.assertTrue(result["error"].startswith("AssertionError: cancel failed"))
                    self.assertIn("supplier cleanup unconfirmed", str(caught.exception.__notes__))
                self.assertFalse((args.output / "result.json").exists())

    def test_case_write_failure_cannot_succeed_or_replace_primary_failure(self):
        for returncode in (0, 37):
            with (
                self.subTest(returncode=returncode),
                owner_fixture(returncode=returncode) as fixture,
            ):
                args, execution, recover, _cases, _children = fixture
                error = OSError if returncode == 0 else AssertionError
                with (
                    mock.patch.object(subject, "save", side_effect=OSError("receipt unavailable")),
                    self.assertRaises(error) as caught,
                ):
                    subject.owner(args, execution)
                execution.stop_process_group.assert_called_once()
                recover.assert_called_once()
                if returncode == 37:
                    self.assertIn("receipt unavailable", str(caught.exception.__notes__))
                self.assertFalse((args.output / "result.json").exists())

    def test_confirmed_cases_keep_existing_success_report(self):
        with owner_fixture() as (args, execution, recover, _cases, _children):
            subject.owner(args, execution)
            self.assertEqual(execution.stop_process_group.call_count, 2)
            self.assertEqual(recover.call_count, 2)
            result = json.loads((args.output / "result.json").read_text())
            self.assertTrue(result["passed"])
            self.assertEqual([r["mode"] for r in result["cases"]], ["cancel", "unconfirmed"])
            for row in result["cases"]:
                self.assertTrue(row["passed"])
                self.assertTrue(row["owned_processes_stopped"])
                self.assertEqual(row, json.loads((args.output / f"{row['mode']}.json").read_text()))

    def test_stale_or_missing_postmaster_record_never_signals(self):
        with tempfile.TemporaryDirectory() as temporary, child() as process:
            directory = Path(temporary)
            pg, data, record = ownership_record(directory, process)
            for mode in ("stale-pidfile", "reused-pid", "missing", "malformed"):
                with self.subTest(mode=mode):
                    (data / "postmaster.pid").write_text(f"{process.pid}\n{data}\n")
                    marker = directory / "postmaster-identity.json"
                    saved = json.loads(json.dumps(record))
                    if mode == "stale-pidfile":
                        saved["identity"] = subject.identity(os.getpid())
                    if mode == "reused-pid":
                        saved["identity"]["starttime"] = "0"
                    marker.write_text(json.dumps(saved) if mode != "malformed" else "{")
                    if mode == "missing":
                        marker.unlink()
                    with (
                        mock.patch.object(subject, "command") as command,
                        mock.patch.object(signal, "pidfd_send_signal") as send,
                        self.assertRaises((AssertionError, ValueError)),
                    ):
                        subject.recover(directory, pg, types.SimpleNamespace())
                    command.assert_not_called()
                    send.assert_not_called()
                    self.assertIsNone(process.poll())
                    self.assertTrue((data / "postmaster.pid").exists())

    def test_capture_checks_actual_executable_argv_and_data(self):
        with tempfile.TemporaryDirectory() as temporary, child() as process:
            directory = Path(temporary)
            pg, data, record = ownership_record(directory, process)
            ownership = subject.postgres_ownership
            (data / "postmaster.pid").write_text(f"{process.pid}\n{data}\n")
            # Even the correct executable is insufficient: this is Python's
            # actual -c argv, not the declared postmaster -D data role.
            with self.assertRaisesRegex(AssertionError, "command/data changed"):
                ownership.capture(pg, data)
            expected = b"\0".join(os.fsencode(v) for v in record["argv"]) + b"\0"
            with mock.patch.object(Path, "read_bytes", return_value=expected):
                self.assertEqual(ownership.capture(pg, data), record)
            for invalid in (expected.rstrip(b"\0"), expected.replace(b"-D", b"-X")):
                with (
                    self.subTest(argv=invalid),
                    mock.patch.object(Path, "read_bytes", return_value=invalid),
                    self.assertRaisesRegex(AssertionError, "command/data changed"),
                ):
                    ownership.capture(pg, data)
            with (
                mock.patch.object(Path, "readlink", return_value=Path("/unrelated/executable")),
                self.assertRaisesRegex(AssertionError, "executable changed"),
            ):
                ownership.capture(pg, data)
            (data / "postmaster.pid").write_text(f"{process.pid}\n/unrelated/data\n")
            with self.assertRaisesRegex(AssertionError, "PID file data mismatch"):
                ownership.capture(pg, data)
            self.assertIsNone(process.poll())

    def test_pidfd_stop_signals_owned_child_and_closes_descriptor(self):
        ownership = subject.postgres_ownership
        real_open = os.pidfd_open
        for mode, signum in (("fast", signal.SIGINT), ("immediate", signal.SIGQUIT)):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory() as temporary,
                postmaster_standin(Path(temporary)) as fixture,
            ):
                process, pg, data, record = fixture
                descriptors = []

                def opened(pid, descriptors=descriptors):
                    descriptor = real_open(pid)
                    descriptors.append(descriptor)
                    return descriptor

                with (
                    mock.patch.object(os, "pidfd_open", side_effect=opened),
                    mock.patch.object(ownership, "inspect_role", return_value=record["identity"]),
                ):
                    ownership.stop(pg, data, record, mode=mode, timeout=1)
                self.assertEqual(process.wait(timeout=3), 0)
                self.assertEqual((Path(temporary) / "signal").read_text(), str(signum))
                self.assertFalse((data / "postmaster.pid").exists())
                self.assertEqual(len(descriptors), 1)
                with self.assertRaises(OSError):
                    os.fstat(descriptors[0])

    def test_stop_revalidates_record_and_refuses_uncertain_ownership(self):
        ownership = subject.postgres_ownership
        with tempfile.TemporaryDirectory() as temporary, child() as process:
            directory = Path(temporary)
            pg, data, record = ownership_record(directory, process)
            (data / "postmaster.pid").write_text(f"{process.pid}\n{data}\n")
            bad_records = [None, {**record, "schema": True}, {**record, "extra": 1}]
            for section, key, value in (
                ("identity", "pid", True),
                ("identity", "starttime", "0"),
                ("identity", "uid", os.getuid() + 1),
                ("data", "inode", record["data"]["inode"] + 1),
                ("data", "device", False),
            ):
                bad_records.append({**record, section: {**record[section], key: value}})
            with mock.patch.object(signal, "pidfd_send_signal") as send:
                for saved in bad_records:
                    with self.subTest(saved=saved), self.assertRaises(AssertionError):
                        ownership.stop(pg, data, saved, mode="immediate", timeout=1)
                # A correct saved snapshot still requires the actual PG role.
                with self.assertRaisesRegex(AssertionError, "command/data changed"):
                    ownership.stop(pg, data, record, mode="immediate", timeout=1)
                send.assert_not_called()
            self.assertIsNone(process.poll())

    def test_pidfd_unavailable_permission_or_live_timeout_cannot_succeed(self):
        ownership = subject.postgres_ownership
        with (
            tempfile.TemporaryDirectory() as temporary,
            postmaster_standin(Path(temporary), ignore=True) as fixture,
        ):
            process, pg, data, record = fixture
            for error in (PermissionError("denied"), OSError("pidfd unsupported")):
                with (
                    self.subTest(error=str(error)),
                    mock.patch.object(os, "pidfd_open", side_effect=error),
                    mock.patch.object(signal, "pidfd_send_signal") as send,
                    self.assertRaises(type(error)),
                ):
                    ownership.stop(pg, data, record, mode="fast", timeout=1)
                send.assert_not_called()
            with (
                mock.patch.object(ownership, "inspect_role", return_value=record["identity"]),
                self.assertRaisesRegex(TimeoutError, "not confirmed"),
            ):
                ownership.stop(pg, data, record, mode="fast", timeout=0.08)
            self.assertIsNone(process.poll())
            self.assertEqual((Path(temporary) / "signal").read_text(), str(signal.SIGINT))
            self.assertTrue((data / "postmaster.pid").exists())

    def test_exit_between_validation_and_pidfd_signal_does_not_target_another_child(self):
        ownership = subject.postgres_ownership
        with tempfile.TemporaryDirectory() as temporary, child() as process, child() as other:
            directory = Path(temporary)
            pg, data, record = ownership_record(directory, process)
            (data / "postmaster.pid").write_text(f"{process.pid}\n{data}\n")
            actual_send = signal.pidfd_send_signal
            calls = []

            def exited_before_signal(descriptor, signum):
                fixture_descriptor = os.pidfd_open(process.pid)
                try:
                    actual_send(fixture_descriptor, signal.SIGTERM)
                finally:
                    os.close(fixture_descriptor)
                process.wait(timeout=3)
                (data / "postmaster.pid").unlink()
                calls.append(signum)
                return actual_send(descriptor, signum)

            with (
                mock.patch.object(ownership, "inspect_role", return_value=record["identity"]),
                mock.patch.object(signal, "pidfd_send_signal", side_effect=exited_before_signal),
                mock.patch.object(os, "kill") as numeric_signal,
            ):
                ownership.stop(pg, data, record, mode="immediate", timeout=1)
            numeric_signal.assert_not_called()
            self.assertEqual(calls, [signal.SIGQUIT])
            self.assertIsNone(other.poll())
            self.assertFalse(Path(f"/proc/{process.pid}").exists())

    def test_start_cancellation_persists_known_owner_and_preserves_primary(self):
        with tempfile.TemporaryDirectory() as temporary, child() as process:
            directory = Path(temporary)
            pg, _data, record = ownership_record(directory, process)
            for mode in ("known", "unknown", "storage-failure", "successful-storage-failure"):
                with self.subTest(mode=mode):
                    marker = directory / "postmaster-identity.json"
                    marker.unlink(missing_ok=True)
                    cluster = {}
                    original = RuntimeError("recorded startup cancellation")

                    def start(*_args, cluster=cluster, mode=mode, original=original, **_kwargs):
                        cluster["postgres_owner"] = None if mode == "unknown" else record
                        if mode == "successful-storage-failure":
                            return subprocess.CompletedProcess([], 0)
                        raise original

                    context = (
                        mock.patch.object(
                            subject, "save", side_effect=OSError("publication denied")
                        )
                        if "storage-failure" in mode
                        else contextlib.nullcontext()
                    )
                    expected = OSError if mode == "successful-storage-failure" else RuntimeError
                    with context, self.assertRaises(expected) as caught:
                        subject.start_postgres(start, pg, directory, cluster)
                    if expected is RuntimeError:
                        self.assertIs(caught.exception, original)
                    if mode == "known":
                        self.assertEqual(json.loads(marker.read_text()), record)
                    else:
                        self.assertFalse(marker.exists())
                    if mode == "storage-failure":
                        self.assertIn("publication denied", str(original.__notes__))


if __name__ == "__main__":
    unittest.main()
