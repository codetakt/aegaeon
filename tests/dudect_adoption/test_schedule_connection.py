# unittest checks must run without pytest and under Python -O.
# ruff: noqa: PT009, PT027
"""Exercise the public scheduling wrapper with the real installation contexts."""

from __future__ import annotations

import contextlib
import importlib
import io
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
        cls.transport = importlib.import_module("dudect_process")

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

    def complete_transport(  # noqa: C901, PLR0913, PLR0915 - keep the transport lifecycle fixture together
        self,
        *,
        deadline=900.5,
        ack=899.8,
        eof=899.85,
        exit_at=899.9,
        finish_at=899.95,
        stalled=False,
        failure=None,
    ):
        """Real scheduler/ACK/receive with only statistics, clock and pipes mocked."""
        stream = object.__new__(self.schedule.Stream)
        stream.absolute_deadline = 900
        stream.deadline = None
        stream.index = stream.total = 0
        stream.cases, stream.buffer = ("fixture",), b""
        stream.before_observation = None
        process = SimpleNamespace(stdout=object(), stdin=io.BytesIO())
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.get_map.side_effect = [True, True, True] if stalled else [True, True, False]
        key = SimpleNamespace(fd=99, fileobj=process.stdout)
        selector.select.return_value = [(key, 1)]

        def observe(obj, _line):
            self.assertEqual(obj.deadline, min(deadline, 900))
            obj.index += 1

        def read(_fd, _size):
            if stream.index == 0:
                clock.return_value = ack
                return b"{}\n"
            clock.return_value = eof
            return b""

        def wait(*, timeout):
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, min(deadline, 900) - eof)
            clock.return_value = exit_at
            return 0

        def finish(_code):
            self.assertEqual(stream.deadline, min(deadline, 900))
            clock.return_value = finish_at

        with (
            patch.object(self.schedule.time, "monotonic", return_value=ack) as clock,
            patch.object(self.schedule.BaseStream, "observe", observe),
            patch.object(stream, "finish", side_effect=finish) as finalize,
            patch.object(self.transport.selectors, "DefaultSelector", return_value=selector),
            patch.object(self.transport.os, "read", side_effect=read),
        ):
            process.wait = Mock(side_effect=wait)
            if stalled:

                def select(timeout):
                    if stream.index == 0:
                        return [(key, 1)]
                    self.assertLessEqual(timeout, 900 - clock.return_value)
                    clock.return_value = 900
                    return []

                selector.select.side_effect = select
            expected = (
                self.assertRaisesRegex(ValueError, failure) if failure else contextlib.nullcontext()
            )
            with expected:
                self.transport.receive(process, io.BytesIO(), stream, deadline, case_budget=900)
            self.assertEqual(process.stdin.getvalue(), b"c")
            self.assertEqual(stream.deadline, min(deadline, 900))
            if stalled or eof >= min(deadline, 900):
                process.wait.assert_not_called()
                finalize.assert_not_called()
            elif exit_at >= min(deadline, 900):
                finalize.assert_not_called()
            else:
                finalize.assert_called_once_with(0)
            if failure is None:
                # collect() uses this same value for its final evidence checks.
                self.assertLess(clock.return_value, stream.deadline)
                clock.return_value = min(deadline, 900)
                self.assertFalse(clock.return_value < stream.deadline)

    def test_on_time_final_ack_cannot_admit_exit_at_or_after_cutoff(self):
        for exit_at in (900, 900.2):
            with self.subTest(exit_at=exit_at):
                self.complete_transport(exit_at=exit_at, failure="deadline.*process exit")

    def test_late_eof_cannot_start_completion_wait(self):
        self.complete_transport(eof=900.2, failure="deadline.*before completion")

    def test_final_ack_cannot_extend_stalled_output_wait(self):
        self.complete_transport(stalled=True, failure="deadline reached")

    def test_finishing_evidence_must_remain_within_cutoff(self):
        self.complete_transport(finish_at=900.2, failure="deadline.*completion")

    def test_success_preserves_cutoff_for_final_evidence_verification(self):
        self.complete_transport()

    def test_stricter_case_deadline_is_preserved(self):
        self.complete_transport(deadline=800, ack=799.5, eof=799.6, exit_at=799.7, finish_at=799.8)

    def stalled_transport(  # noqa: C901, PLR0915 - keep the silent-wait lifecycle fixture together
        self, *, cutoff=900, renew=False, initial_time=899.8, deadline=900.5
    ):
        """Bound silent waits using the real scheduler, consume and transport."""
        process = SimpleNamespace(stdout=object(), stdin=io.BytesIO(), wait=Mock())
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.get_map.return_value = True
        key = SimpleNamespace(fd=99, fileobj=process.stdout)
        waits = []

        def initialize(obj):
            obj.deadline = obj.before_observation = None
            obj.index = obj.total = 0
            obj.cases = ("first", "second") if renew else ("first",)
            obj.buffer = b""
            clock.return_value += 0.5

        def observe(obj, _line):
            obj.index += 1

        def flush():
            # Time between the next-case budget check and budget renewal.
            clock.return_value += 0.5

        def select(timeout):
            waits.append((clock.return_value, timeout))
            if renew and stream.index == 0:
                return [(key, 1)]
            clock.return_value += timeout
            return []

        with (
            patch.object(self.schedule.time, "monotonic", return_value=0) as clock,
            patch.object(self.schedule.BaseStream, "__init__", initialize),
            patch.object(self.schedule.BaseStream, "observe", observe),
            patch.object(self.transport.ObservationStream, "observe", observe),
            patch.object(self.transport.selectors, "DefaultSelector", return_value=selector),
            patch.object(self.transport.os, "read", return_value=b"{}\n"),
        ):
            if cutoff is None:
                stream = object.__new__(self.transport.ObservationStream)
                initialize(stream)
            else:
                stream = self.schedule.Stream(absolute_deadline=cutoff)
            self.assertEqual(clock.return_value, 0.5)
            clock.return_value = initial_time
            process.stdin.flush = flush
            selector.select.side_effect = select
            with self.assertRaisesRegex(ValueError, "deadline reached"):
                self.transport.receive(process, io.BytesIO(), stream, deadline, case_budget=900)
            expected = initial_time + 0.5 + 900 if renew else deadline
            if cutoff is not None:
                expected = min(expected, cutoff)
            self.assertEqual(clock.return_value, max(initial_time, expected))
            if cutoff is not None and stream.deadline is not None:
                self.assertEqual(stream.deadline, expected)
            for started, timeout in waits:
                self.assertLessEqual(started + timeout, expected)
            self.assertEqual(process.stdin.getvalue(), b"c" if renew else b"")
            process.wait.assert_not_called()
            if initial_time >= expected:
                selector.select.assert_not_called()

    def test_stall_before_first_observation_obeys_acquisition_cutoff(self):
        self.stalled_transport()

    def test_expired_cutoff_never_starts_first_selector_wait(self):
        self.stalled_transport(initial_time=900)

    def test_case_budget_renewal_cannot_extend_acquisition_wait(self):
        self.stalled_transport(cutoff=1000, renew=True, initial_time=100)

    def test_silent_first_case_preserves_stricter_case_limit(self):
        self.stalled_transport(deadline=800, initial_time=799.8)

    def test_silent_unscheduled_stream_keeps_original_case_limit(self):
        self.stalled_transport(cutoff=None)

    def test_unscheduled_stream_still_renews_completed_case_budget(self):
        self.stalled_transport(cutoff=None, renew=True, initial_time=100)


if __name__ == "__main__":
    unittest.main()
