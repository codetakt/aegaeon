# unittest checks must run without pytest and under Python -O.
# ruff: noqa: PT009, PT027
"""Exercise the public scheduling wrapper with the real installation contexts."""

from __future__ import annotations

import importlib
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

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
