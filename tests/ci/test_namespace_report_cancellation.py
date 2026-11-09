"""Cancellation during final reporting cannot turn namespace work into success."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions remain active under Python -O.
import contextlib
import json
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import with_organization_userns as subject  # noqa: E402


class ReportFixture:
    def __init__(self, test, directory, case):
        self.test = test
        self.phase, self.signum, self.code, self.fault = case
        self.report = directory / "reports" / "namespace.json"
        self.namespace = directory / "namespace"
        self.namespace.mkdir()
        self.calls = {"writes": 0, "signals": 0, "context_exited": False}
        self.children = []
        self.original_write, self.original_mkdir = Path.write_text, Path.mkdir
        self.original_initialize = subject.nested_cleanup.initialize
        self.original_popen, self.original_run = subject.subprocess.Popen, subject.run_command

    def cancel(self, point):
        if self.phase == point:
            self.calls["signals"] += 1
            os.kill(os.getpid(), self.signum)

    def fail(self, point):
        if self.fault == point:
            raise OSError("controlled " + point + " failure")

    def mkdir(self, path, *args, **kwargs):
        if path == self.report.parent:
            self.cancel("mkdir")
            self.fail("mkdir")
        return self.original_mkdir(path, *args, **kwargs)

    def write(self, path, data, *args, **kwargs):
        if path == self.report:
            self.calls["writes"] += 1
            self.cancel("write")
            if self.calls["writes"] == 2:
                self.test.assertTrue(self.calls["context_exited"])
                self.cancel("rewrite")
                self.fail("rewrite")
            self.fail("write")
        result = self.original_write(path, data, *args, **kwargs)
        if path == self.report:
            self.cancel("after_write")
        return result

    @contextlib.contextmanager
    def initialize(self, *args, **kwargs):
        with self.original_initialize(*args, **kwargs) as identity:
            yield identity
        self.calls["context_exited"] = True
        # This boundary follows release of both actual pinned descriptors.
        self.cancel("context_exit")
        if self.phase == "rewrite":
            os.kill(os.getpid(), self.signum)
            self.calls["signals"] += 1
        self.fail("context_exit")

    def popen(self, *args, **kwargs):
        child = self.original_popen(*args, **kwargs)
        self.children.append(child)
        return child

    def run(self, *args, **kwargs):
        status = self.original_run(*args, **kwargs)
        if self.fault == "work":
            message = "controlled work failure"
            raise ValueError(message)
        return status

    @contextlib.contextmanager
    def installed(self):
        # Plain functions preserve descriptor binding for Path instance methods.
        def mkdir(path, *args, **kwargs):
            return self.mkdir(path, *args, **kwargs)

        def write(path, *args, **kwargs):
            return self.write(path, *args, **kwargs)

        with (
            patch.object(subject, "restriction", return_value="1"),
            patch.object(
                subject,
                "prepare",
                side_effect=lambda _p, _n, r: r.update(before={"passed": True, "attempts": []}),
            ),
            patch.object(subject.tempfile, "mkdtemp", return_value=str(self.namespace)),
            patch.object(subject.subprocess, "Popen", self.popen),
            patch.object(subject, "run_command", self.run),
            patch.object(subject.nested_cleanup, "initialize", self.initialize),
            patch.object(Path, "mkdir", mkdir),
            patch.object(Path, "write_text", write),
            patch.object(
                sys,
                "argv",
                [
                    "with_organization_userns.py",
                    "--report",
                    str(self.report),
                    "--",
                    sys.executable,
                    "-c",
                    f"raise SystemExit({self.code})",
                ],
            ),
        ):
            yield

    def invoke(self):
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        status, error = None, None
        try:
            with self.installed():
                try:
                    status = subject.main()
                except OSError as caught:
                    error = str(caught)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            self.reap()
            subject._cancellation = None
            subject._unconfirmed_groups.clear()
        self.test.assertEqual(len(self.children), 1)
        self.test.assertEqual(self.children[0].returncode, self.code)
        self.test.assertFalse(self.namespace.exists())
        row = json.loads(self.report.read_text()) if self.report.exists() else None
        return status, error, row, self.calls

    def reap(self):
        for child in self.children:
            subject.stop_process_group(child, grace=0)
            child.wait(timeout=2)
            self.test.assertFalse(Path(f"/proc/{child.pid}").exists())


class NamespaceReportCancellationTests(unittest.TestCase):
    def scenario(self, phase="none", *, signum=signal.SIGTERM, code=0, fault="none"):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReportFixture(self, Path(temporary), (phase, signum, code, fault))
            return fixture.invoke()

    def test_uninterrupted_status_is_preserved_without_rewrite(self):
        for code in (0, 37):
            with self.subTest(code=code):
                status, error, row, calls = self.scenario(code=code)
                self.assertEqual(status, code)
                self.assertIsNone(error)
                self.assertNotIn("cancellation", row)
                self.assertEqual(calls["writes"], 1)

    def test_report_mkdir_cancellation_fails_after_cleanup(self):
        self.assert_cancellation("mkdir")

    def test_report_write_cancellation_fails_after_cleanup(self):
        for phase in ("write", "after_write"):
            for signum in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(phase=phase, signum=signum):
                    self.assert_cancellation(phase, signum=signum)

    def test_context_exit_cancellation_fails_after_reporting(self):
        self.assert_cancellation("context_exit")

    def test_repeated_cancellation_requires_only_one_rewrite(self):
        self.assert_cancellation("rewrite")

    def assert_cancellation(self, phase, **kwargs):
        status, error, row, calls = self.scenario(phase, **kwargs)
        self.assertEqual(status, 1)
        self.assertIsNone(error)
        self.assertIn("interrupted by signal", row["cancellation"])
        self.assertTrue(calls["context_exited"])
        self.assertEqual(calls["writes"], 2)
        self.assertGreater(calls["signals"], 0)
        self.assertEqual(row["unconfirmed_groups"], [])

    def test_late_cancellation_preserves_nonzero_and_work_error(self):
        status, error, row, _ = self.scenario("write", code=37)
        self.assertEqual(status, 37)
        self.assertIsNone(error)
        self.assertEqual(row["command_returncode"], 37)
        status, error, row, _ = self.scenario("write", fault="work")
        self.assertEqual(status, 1)
        self.assertIsNone(error)
        self.assertEqual(row["error"], "controlled work failure")
        self.assertIn("cancellation", row)

    def test_report_and_context_errors_never_return_success(self):
        for fault in ("mkdir", "write", "context_exit", "rewrite"):
            with self.subTest(fault=fault):
                phase = "context_exit" if fault == "rewrite" else fault
                status, error, _, calls = self.scenario(phase, fault=fault)
                self.assertIsNone(status)
                self.assertEqual(error, "controlled " + fault + " failure")
                self.assertTrue(calls["context_exited"] or fault in ("mkdir", "write"))
                self.assertLessEqual(calls["writes"], 2)


if __name__ == "__main__":
    unittest.main()
