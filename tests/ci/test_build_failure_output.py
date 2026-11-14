"""Real child stderr remains available when group cleanup cannot be confirmed."""

from __future__ import annotations

# ruff: noqa: PT009 - unittest owns and independently reclaims each actual child.
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


class BuildFailureOutputTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.children = []
        self.records = []
        self.real_popen, self.real_read = subprocess.Popen, os.read
        self.addCleanup(self.recover)

    def recover(self):
        for child in self.children:
            execution.stop_process_group(child, grace=0.1)
            if child.stderr is not None:
                child.stderr.close()

    def scenario(  # noqa: C901, PLR0913, PLR0915 - one child/receipt/fault boundary.
        self,
        kind,
        code=37,
        *,
        delivery_fault=False,
        trace_fault=False,
        helper_fault=False,
        selector_fault=False,
    ):
        directory = self.directory / str(len(self.records))
        directory.mkdir()
        release, ready = directory / "release", directory / "ready"
        script = directory / "child.py"
        first = b"pending fragment" if kind.startswith("pending") else b"unread explanation\n"
        script.write_text(
            "import os,sys,time\nfrom pathlib import Path\n"
            f"os.write(2,{first!r})\n"
            f"Path({str(ready)!r}).write_text('ready')\n"
            + (
                "until=time.monotonic()+4\n"
                f"while not Path({str(release)!r}).exists() and time.monotonic()<until:\n"
                " time.sleep(.005)\n"
                "os.write(2,b' and unread tail\\n')\n"
                if kind.startswith("pending")
                else ""
            )
            + f"sys.exit({code})\n"
        )
        command = [sys.executable, str(script)]
        cleanup_error = TimeoutError("injected group confirmation refusal")
        forwarded = io.BytesIO()
        real_forward_write = forwarded.write
        real_open = Path.open
        real_capture = (
            build.preserve_failure_output if hasattr(build, "preserve_failure_output") else None
        )
        real_selector = build.selectors.DefaultSelector

        def delivery(data):
            if delivery_fault:
                raise OSError("injected stderr sink failure")  # noqa: EM101, TRY003
            return real_forward_write(data)

        class Trace:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __enter__(self):
                return self

            def write(self, text):
                if '"event": "finish"' in text:
                    raise OSError("injected finish record failure")  # noqa: EM101, TRY003
                return self.wrapped.write(text)

            def flush(self):
                return self.wrapped.flush()

            def __exit__(self, *_args):
                self.wrapped.close()
                raise OSError("injected trace close failure")  # noqa: EM101, TRY003

        def opened(path, *args, **kwargs):
            result = real_open(path, *args, **kwargs)
            return Trace(result) if trace_fault and path == directory / "trace.jsonl" else result

        def capture(*args):
            if helper_fault:
                raise OSError("injected recovery helper failure")  # noqa: EM101, TRY003
            return real_capture(*args)

        def selector():
            if selector_fault:
                raise OSError("injected selector construction failure")  # noqa: EM101, TRY003
            return real_selector()

        read_triggered = False

        def spawn(*args, **kwargs):
            child = self.real_popen(*args, **kwargs)
            self.children.append(child)
            if not kind.startswith("pending"):
                self.assertEqual(child.wait(timeout=3), code)
            return child

        def read(fd, size):
            nonlocal read_triggered
            pipe = self.children[-1].stderr if self.children else None
            target = pipe is not None and not pipe.closed and fd == pipe.fileno()
            if target and kind == "pending-read-error" and not os.get_blocking(fd):
                raise OSError("injected recovery read failure")  # noqa: EM101, TRY003
            chunk = self.real_read(fd, size)
            if target and chunk and kind.startswith("pending") and not read_triggered:
                read_triggered = True
                release.write_text("release")
                self.assertEqual(self.children[-1].wait(timeout=3), code)
            return chunk

        receipts, trace = directory / "receipts", directory / "trace.jsonl"
        with (
            build.cleanup_receipts.initialize(receipts, f"aegaeon-userns-{len(self.records):032x}"),
            mock.patch.dict(os.environ, {build.cleanup_receipts.ENVIRONMENT: str(receipts)}),
            mock.patch.object(build.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(build.os, "read", side_effect=read),
            mock.patch.object(build, "stop_process_group", side_effect=cleanup_error),
            mock.patch.object(
                build.sys,
                "stderr",
                SimpleNamespace(buffer=SimpleNamespace(write=delivery, flush=forwarded.flush)),
            ),
            mock.patch.object(Path, "open", opened),
            mock.patch.object(build, "preserve_failure_output", side_effect=capture, create=True),
            mock.patch.object(build.selectors, "DefaultSelector", side_effect=selector),
        ):
            started = time.monotonic()
            try:
                build.run_observed(command, trace)
            except BaseException as failure:  # noqa: BLE001 - preserve actual result before independent recovery.
                error = failure
            else:
                self.fail("unconfirmed cleanup succeeded")
            elapsed = time.monotonic() - started
        child = self.children[-1]
        rows = [json.loads(line) for line in trace.read_text().splitlines()]
        registration = [
            json.loads(p.read_text()) for p in receipts.glob("*.json") if p.name != "owner.json"
        ]
        record = {
            "kind": kind,
            "code": code,
            "pid": child.pid,
            "elapsed": elapsed,
            "error": type(error).__name__,
            "message": str(error),
            "returncode": getattr(error, "returncode", None),
            "cause": type(error.__cause__).__name__,
            "notes": getattr(error, "__notes__", []),
            "forwarded": forwarded.getvalue().decode(),
            "trace": rows,
            "observed_stderr": getattr(error, "observed_stderr", b"").decode(),
            "capture": getattr(error, "stderr_recovery", None),
            "receipts": registration,
            "live_before_recovery": execution.group_running(child.pid),
        }
        self.records.append(record)
        self.assertEqual(len(registration), 1, record)
        self.assertFalse(registration[0]["confirmed"], record)
        if trace_fault:
            self.assertFalse(any(r["event"] == "finish" for r in rows), record)
        else:
            self.assertEqual(rows[-1]["returncode"], None if selector_fault else code, record)
        if selector_fault:
            self.assertIsInstance(error, OSError, record)
        elif code:
            self.assertIsInstance(error, subprocess.CalledProcessError, record)
            self.assertEqual(error.returncode, code, record)
            self.assertIs(error.__cause__, cleanup_error, record)
        else:
            self.assertIs(error, cleanup_error, record)
        return error, record

    def test_unread_stderr_survives_observed_exit_and_cleanup_failure(self):
        for code in (37, 0):
            with self.subTest(code=code):
                _, record = self.scenario("unread", code)
                self.assertEqual(record["forwarded"], "unread explanation\n", record)
                self.assertEqual(
                    "".join(r["text"] for r in record["trace"] if r["event"] == "output"),
                    record["forwarded"],
                    record,
                )

    def test_failure_closes_pipe_before_independent_recovery(self):
        for code in (37, 0):
            with self.subTest(code=code):
                _, record = self.scenario("unread", code)
                closed = self.children[-1].stderr.closed
                record["source_pipe_closed_before_independent_recovery"] = closed
                self.assertTrue(closed, record)

    def test_pending_partial_and_unread_tail_survive_cleanup_failure(self):
        _, record = self.scenario("pending")
        self.assertEqual(record["forwarded"], "pending fragment and unread tail\n", record)
        self.assertEqual(
            "".join(r["text"] for r in record["trace"] if r["event"] == "output"),
            record["forwarded"],
            record,
        )

    def test_secondary_capture_and_forward_errors_preserve_command_failure(self):
        error, record = self.scenario("pending-read-error")
        self.assertEqual(error.observed_stderr, b"pending fragment", record)
        self.assertEqual(record["capture"]["reason"], "capture_error", record)
        self.assertEqual(record["capture"]["capture_error"], "OSError", record)
        error, record = self.scenario("unread", delivery_fault=True)
        self.assertEqual(error.stderr, b"unread explanation\n", record)
        self.assertEqual(record["capture"]["forward_errors"], ["OSError"], record)
        _, record = self.scenario("unread", helper_fault=True)
        self.assertIn("stderr recovery failed: OSError", record["notes"], record)

    def test_finish_and_close_errors_do_not_replace_cleanup_cause(self):
        error, record = self.scenario("unread", trace_fault=True)
        self.assertEqual(error.stderr, b"unread explanation\n", record)
        self.assertIn("observation finish record failed: OSError", record["notes"], record)
        self.assertIn("observation trace close failed: OSError", record["notes"], record)

    def test_selector_failure_keeps_registered_group_and_available_output(self):
        _, record = self.scenario("unread", selector_fault=True)
        self.assertEqual(record["receipts"][0]["group"], record["pid"], record)
        self.assertEqual(record["forwarded"], "unread explanation\n", record)

    def live_case(self, mode):  # noqa: C901, PLR0915 - one bounded actual writer and independent cleanup.
        directory = self.directory / str(len(self.records))
        directory.mkdir()
        ready = directory / "ready"
        payload = b"held partial"
        script = directory / "live-child.py"
        script.write_text(
            "import os,time\nfrom pathlib import Path\n"
            f"os.write(2,{payload!r})\n"
            + ("os.write(2,b'x'*4096)\n" if mode == "byte-limit" else "")
            + f"Path({str(ready)!r}).write_text('ready')\n"
            + (
                "while True: os.write(2,b'x'*4096)\n"
                if mode == "byte-limit"
                else "time.sleep(10)\n"
            )
        )
        command = [sys.executable, str(script)]
        original = subprocess.TimeoutExpired(command, 0.1)
        triggered = False
        spawned = False
        calls = []
        forwarded = []
        primary = None
        real_check = build.check_cancellation
        cleanup_error = TimeoutError("injected group confirmation refusal")

        def spawn(*args, **kwargs):
            nonlocal spawned
            child = self.real_popen(*args, **kwargs)
            self.children.append(child)
            spawned = True
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertTrue(ready.exists())
            if mode == "cancel":
                os.kill(os.getpid(), signal.SIGTERM)
            return child

        def check():
            nonlocal primary
            if spawned and (
                triggered or mode in ("cancel", "byte-limit", "read-limit", "time-limit")
            ):
                if mode == "cancel":
                    try:
                        real_check()
                    except BaseException as error:
                        primary = error
                        raise
                primary = original
                raise original
            real_check()

        def read(fd, size):
            nonlocal triggered
            pipe = self.children[-1].stderr if self.children else None
            target = pipe is not None and not pipe.closed and fd == pipe.fileno()
            if target and not os.get_blocking(fd):
                calls.append(size)
                if mode == "read-limit":
                    raise InterruptedError("injected interrupted nonblocking read")  # noqa: EM101, TRY003
            data = self.real_read(fd, size)
            if target and data:
                triggered = True
            return data

        def forward(data):
            forwarded.append(data)
            if mode == "forward-primary":
                raise original

        limit = 4096 if mode == "byte-limit" else build.FAILURE_STDERR_BYTES
        seconds = 0 if mode == "time-limit" else build.FAILURE_STDERR_SECONDS
        with (
            mock.patch.object(build.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(build.os, "read", side_effect=read),
            mock.patch.object(build, "check_cancellation", side_effect=check),
            mock.patch.object(build, "stop_process_group", side_effect=cleanup_error),
            mock.patch.object(build, "FAILURE_STDERR_BYTES", limit),
            mock.patch.object(build, "FAILURE_STDERR_SECONDS", seconds),
        ):
            started = time.monotonic()
            try:
                with execution.cancellation_scope():
                    build.observe_process(command, forward)
            except BaseException as error:  # noqa: BLE001 - save all source outcomes before independent recovery.
                failure = error
            else:
                self.fail("expected original failure")
            elapsed = time.monotonic() - started
        child = self.children[-1]
        live = child.poll() is None
        execution.stop_process_group(child, grace=0.1)
        record = {
            "mode": mode,
            "pid": child.pid,
            "error": type(failure).__name__,
            "primary_same": failure is (primary or original),
            "elapsed": elapsed,
            "captured_bytes": len(getattr(failure, "observed_stderr", b"")),
            "capture": getattr(failure, "stderr_recovery", None),
            "calls": len(calls),
            "forwarded": [c.decode() for c in forwarded],
            "notes": getattr(failure, "__notes__", []),
            "writer_live_before_recovery": live,
            "remaining_group": execution.group_running(child.pid),
        }
        self.records.append(record)
        self.assertTrue(record["primary_same"], record)
        self.assertFalse(record["remaining_group"], record)
        self.assertLess(elapsed, 4, record)
        self.assertLessEqual(record["captured_bytes"], limit, record)
        self.assertLessEqual(len(calls), build.FAILURE_STDERR_READS, record)
        if mode != "byte-limit":
            self.assertTrue(live, record)
        return failure, record

    def test_snapshot_never_waits_for_live_writer_eof(self):
        error, record = self.live_case("held-empty")
        self.assertEqual(error.observed_stderr, b"held partial", record)
        self.assertEqual(record["capture"]["reason"], "would_block", record)
        error, record = self.live_case("cancel")
        self.assertIsInstance(error, SystemExit, record)
        self.assertEqual(error.code, 143, record)
        self.assertEqual(error.observed_stderr, b"held partial", record)

    def test_snapshot_records_byte_time_and_read_limits(self):
        for mode in ("byte-limit", "time-limit", "read-limit"):
            with self.subTest(mode=mode):
                _, record = self.live_case(mode)
                self.assertEqual(record["capture"]["reason"], mode.replace("-", "_"), record)

    def test_failed_inflight_forward_is_retained_without_resending(self):
        # A newline makes the normal forward path fail while the real writer stays alive.
        # The separately held-pipe fixtures cover the no-newline pending path.
        original = subprocess.TimeoutExpired(["fixture"], 0.1)
        child = self.real_popen(
            [sys.executable, "-c", "import os,time;os.write(2,b'inflight\\n');time.sleep(10)"],
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.children.append(child)
        attempts = []

        def forward(data):
            attempts.append(data)
            raise original

        with (
            mock.patch.object(build.subprocess, "Popen", return_value=child),
            mock.patch.object(build, "stop_process_group", side_effect=TimeoutError("unconfirmed")),
        ):
            try:
                build.observe_process(["already owned fixture child"], forward)
            except BaseException as error:  # noqa: BLE001 - exact primary preservation is the assertion.
                failure = error
        self.assertIs(failure, original)
        self.assertEqual(attempts, [b"inflight\n"])
        self.assertEqual(failure.observed_stderr, b"inflight\n")
        self.assertEqual(failure.stderr_recovery["attempted_bytes_not_resent"], len(b"inflight\n"))
        self.assertIsNone(child.poll())


if __name__ == "__main__":
    unittest.main()
