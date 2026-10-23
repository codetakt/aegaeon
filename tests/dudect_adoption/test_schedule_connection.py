# unittest checks must run without pytest and under Python -O.
# ruff: noqa: PT009, PT027
"""Exercise the public scheduling wrapper with the real installation contexts."""

from __future__ import annotations

import contextlib
import importlib
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from test_optional_reporting import REPORT

ROOT = Path(__file__).resolve().parents[2]


class ScheduleConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = sys.path.copy()
        for directory in (
            "dudect_analysis",
            "dudect_sensitivity",
            "dudect_calibration_scope",
            "dudect_sensitivity_control_roles",
            "dudect_sensitivity_live",
            "dudect_sensitivity_operations",
        ):
            sys.path.insert(0, str(ROOT / "tests" / directory))
        cls.ordinary = importlib.import_module("ordinary")
        cls.live = importlib.import_module("live_runtime")
        cls.runtime = importlib.import_module("analysis_runtime")
        cls.schedule = importlib.import_module("schedule")
        cls.candidate = importlib.import_module("run_candidate")

    @classmethod
    def tearDownClass(cls):
        sys.path[:] = cls.paths

    def run_installed(self, fail=False):
        before = (self.runtime.Stream, self.candidate.RuntimeStream, self.candidate.Worker)
        deadline = time.monotonic() + 1800

        def execute():
            self.assertIsNot(self.runtime.Stream, before[0])
            with self.live.installed({"fixture": True}):
                self.assertIs(self.candidate.RuntimeStream, self.runtime.Stream)
                # Native collection uses this exact factory. Exercise the real
                # schedule constructor without running measurement initialization.
                with patch.object(self.schedule.BaseStream, "__init__", return_value=None):
                    stream = self.candidate.RuntimeStream()
                self.assertIsInstance(stream, self.schedule.Stream)
                self.assertEqual(stream.absolute_deadline, deadline)
                if fail:
                    raise OSError
                return "completed"

        with patch.object(self.ordinary, "execute", side_effect=execute):
            if fail:
                with self.assertRaises(OSError):
                    REPORT.scheduled_ordinary(deadline)
            else:
                self.assertEqual(REPORT.scheduled_ordinary(deadline), "completed")
        self.assertEqual(
            (self.runtime.Stream, self.candidate.RuntimeStream, self.candidate.Worker), before
        )

    def test_schedule_installed_before_live_and_restored(self):
        self.run_installed()

    def test_exception_restores_both_contexts(self):
        self.run_installed(fail=True)

    def test_invalid_cutoff_never_starts_measurement(self):
        for cutoff in (time.monotonic() - 1, time.monotonic() + 899, float("nan"), float("inf")):
            with patch.object(self.ordinary, "execute") as execute:
                with self.assertRaises(ValueError):
                    REPORT.scheduled_ordinary(cutoff)
                execute.assert_not_called()

    def collect_executables(self, after_first=100, fail_launch=False):  # noqa: PLR0915 -- keep the real collector lifecycle fixture together
        """Keep execute/collect/Stream real; replace only external I/O and replay.

        The transport supplies no timing samples. This tests launch admission,
        attachment and cleanup, not native measurement or statistical acceptance.
        """
        before = (self.runtime.Stream, self.candidate.RuntimeStream, self.candidate.Worker)
        index = {
            "executables": [
                {"name": name, "relative_binary": name, "cases": [name]}
                for name in ("first", "second")
            ]
        }
        bindings = {name: {} for name in ("first", "second")}
        workers, streams, launches = [], [], []

        def worker(*_args, **kwargs):
            obj = SimpleNamespace(analysis=kwargs["analysis"], analysis_journal=None)
            obj.close = lambda: obj.analysis_journal.close() if obj.analysis_journal else None
            workers.append(obj)
            return obj

        def launch(argv, **_kwargs):
            launches.append(argv)
            if fail_launch:
                message = "fixture launch failure"
                raise OSError(message)
            return SimpleNamespace(pid=1234, argv=argv)

        def receive(process, _output, stream, _deadline, **_kwargs):
            self.assertIsInstance(stream, self.candidate.RuntimeStream)
            self.assertIsInstance(stream, self.schedule.Stream)
            self.assertEqual(stream.absolute_deadline, 1100)
            streams.append(stream)
            stream.deadline = min(clock.return_value + 900, stream.absolute_deadline)
            Path(process.argv[3]).write_text(
                json.dumps({"pid": process.pid, "native": [1], "argv": process.argv[4:]})
            )
            if len(streams) == 1:
                clock.return_value = after_first

        report = {"fixture": True}
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(self.schedule.time, "monotonic", return_value=100) as clock,
            patch.object(self.ordinary.signal, "signal"),
            patch.object(self.ordinary, "checked_package", return_value=index),
            patch.object(self.candidate, "current_sources", return_value={}),
            patch.object(self.ordinary, "identity", return_value={"fixture": True}),
            patch.object(self.ordinary, "expected_bindings", return_value={"bindings": bindings}),
            patch.object(self.ordinary, "verify", return_value=report) as verify,
            patch.object(self.live, "Worker", side_effect=worker),
            patch.object(
                self.candidate,
                "collector_placement",
                side_effect=lambda: contextlib.nullcontext({"native": [1], "collector": [0]}),
            ),
            patch.object(self.candidate, "RuntimeCapture", return_value=Mock()),
            patch.object(self.candidate.subprocess, "Popen", side_effect=launch),
            patch.object(self.candidate, "receive", side_effect=receive),
            patch.object(self.candidate, "terminate", return_value=0),
            patch.object(self.candidate, "validate_timing", return_value={}),
        ):
            output = Path(directory) / "collection"
            args = (1100, Path(directory), output, "legacy", "packet", "unit")
            if fail_launch or after_first > 200:
                error_type = OSError if fail_launch else ValueError
                reason = "fixture launch failure" if fail_launch else "budget for executable"
                with self.assertRaisesRegex(error_type, reason):
                    REPORT.scheduled_ordinary(*args)
                self.assertEqual(
                    json.loads((output / "failure.json").read_bytes())["type"], error_type.__name__
                )
                verify.assert_not_called()
                self.assertEqual(len(launches), 1)
                self.assertEqual(len(workers), 1)
            else:
                self.assertEqual(REPORT.scheduled_ordinary(*args), report)
                verify.assert_called_once()
                self.assertEqual(len(launches), 2)
                self.assertEqual(len(streams), 2)
            self.assertTrue(all(w.analysis_journal.closed for w in workers))
        self.assertEqual(
            (self.runtime.Stream, self.candidate.RuntimeStream, self.candidate.Worker), before
        )

    def test_public_wrapper_runs_real_collection_setup_for_each_executable(self):
        self.collect_executables()

    def test_next_executable_with_exactly_900_seconds_is_allowed(self):
        self.collect_executables(after_first=200)

    def test_next_executable_with_899_seconds_is_rejected_before_worker_or_native(self):
        self.collect_executables(after_first=201)

    def test_collection_launch_failure_restores_contexts_and_closes_journal(self):
        self.collect_executables(fail_launch=True)

    def test_stream_rechecks_cutoff_before_initialization(self):
        with (
            patch.object(self.schedule.time, "monotonic", return_value=100) as clock,
            self.schedule.installed(1100),
            self.live.installed({"fixture": True}),
        ):
            for now in (200.001, 1100, 1200):
                clock.return_value = now
                with (
                    self.subTest(now=now),
                    patch.object(self.schedule.BaseStream, "__init__") as initialize,
                    self.assertRaisesRegex(ValueError, "budget for executable"),
                ):
                    self.candidate.RuntimeStream(("fixture",), "pr", bindings={"fixture": {}})
                initialize.assert_not_called()

    def test_installed_rejects_nonfinite_cutoff_without_changing_factory(self):
        before = self.runtime.Stream
        for cutoff in (float("nan"), float("inf"), float("-inf")):
            with (
                self.subTest(cutoff=cutoff),
                self.assertRaises(ValueError),
                self.schedule.installed(cutoff),
            ):
                self.fail("invalid cutoff was installed")
            self.assertIs(self.runtime.Stream, before)

    def test_real_stream_withholds_ack_when_next_case_does_not_fit(self):
        stream = object.__new__(self.schedule.Stream)
        stream.deadline, stream.absolute_deadline = 2000, 1500
        stream.index, stream.cases = 0, ["one", "two"]

        def consume(obj, _line):
            obj.index += 1

        with (
            patch.object(self.schedule.BaseStream, "observe", consume),
            patch.object(self.schedule.time, "monotonic", return_value=700),
            self.assertRaisesRegex(ValueError, "ACK withheld"),
        ):
            stream.observe(b"fixture")
        self.assertEqual(stream.deadline, 1500)

    def test_reversed_installation_does_not_capture_schedule(self):
        # Regression demonstrates the specific original hazard; the public
        # wrapper's successful path above must not use this ordering.
        with self.live.installed({"fixture": True}):
            captured = self.candidate.RuntimeStream
            with self.schedule.installed(time.monotonic() + 1800):
                self.assertIs(self.candidate.RuntimeStream, captured)
                self.assertIsNot(captured, self.runtime.Stream)


if __name__ == "__main__":
    unittest.main()
