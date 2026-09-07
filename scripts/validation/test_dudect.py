"""Reject timing warning bands and invalid acceptance policies."""

from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import check_dudect as validator
import pytest


class DudectThresholdTests(unittest.TestCase):
    def evaluate(
        self, metrics: validator.Metrics, environment: dict[str, str] | None = None
    ) -> tuple[int, str]:
        output = io.StringIO()
        with (
            patch.dict(os.environ, environment or {}, clear=True),
            patch.object(validator, "load_dudect_results", return_value=metrics),
            redirect_stdout(output),
            redirect_stderr(output),
        ):
            result = validator.main()
        return result, output.getvalue()

    def test_default_tau_warning_band_is_preserved(self) -> None:
        for tau, expected_status, message in (
            (3.0, 0, "passed"),
            (3.5, 0, "passed"),
            (4.0, 1, "warning band"),
            (4.5, 1, "warning band"),
            (5.0, 1, "exceeds fail threshold"),
        ):
            for sign in (-1, 1):
                with self.subTest(tau=tau * sign):
                    status, output = self.evaluate(
                        validator.Metrics(tau=tau * sign, num_traces=16_000)
                    )
                    assert status == expected_status
                    assert message in output
                    assert "adjusting" not in output

    def test_p_value_bands_retain_the_opposite_direction(self) -> None:
        for p_value, expected_status, message in (
            (0.1, 0, "passed"),
            (0.05, 0, "passed"),
            (0.03, 1, "warning band"),
            (0.01, 1, "warning band"),
            (0.001, 1, "below fail threshold"),
        ):
            with self.subTest(p_value=p_value):
                status, output = self.evaluate(
                    validator.Metrics(p_value=p_value, num_traces=16_000)
                )
                assert status == expected_status
                assert message in output

    def test_invalid_thresholds_cannot_be_silently_normalized(self) -> None:
        invalid = (
            {"DUDECT_TAU_WARN": "5"},
            {"DUDECT_TAU_WARN": "4.5"},
            {"DUDECT_TAU_WARN": "0"},
            {"DUDECT_TAU_FAIL": "-1"},
            {"DUDECT_WARN_THRESHOLD": "0.001"},
            {"DUDECT_WARN_THRESHOLD": "1.1"},
            {"DUDECT_FAIL_THRESHOLD": "0.05"},
            {"DUDECT_FAIL_THRESHOLD": "-1"},
            {"DUDECT_MIN_TRACES": "0"},
            {"DUDECT_MIN_TRACES": "-1"},
        )
        for environment in invalid:
            with self.subTest(environment=environment), pytest.raises(ValueError, match="DUDECT_"):
                self.evaluate(validator.Metrics(tau=0.0, num_traces=16_000), environment)

    def test_non_finite_and_malformed_configuration_is_rejected(self) -> None:
        for key in (
            "DUDECT_TAU_WARN",
            "DUDECT_TAU_FAIL",
            "DUDECT_WARN_THRESHOLD",
            "DUDECT_FAIL_THRESHOLD",
        ):
            for value in ("nan", "inf", "-inf", "invalid"):
                with self.subTest(key=key, value=value), pytest.raises(ValueError, match=key):
                    self.evaluate(validator.Metrics(tau=0.0, num_traces=16_000), {key: value})

    def test_non_finite_evidence_cannot_pass_comparisons(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            for field in ("tau", "p_value"):
                metrics = validator.Metrics(num_traces=16_000)
                setattr(metrics, field, value)
                with (
                    self.subTest(field=field, value=value),
                    pytest.raises(ValueError, match="must be finite"),
                ):
                    self.evaluate(metrics)

    def test_missing_evidence_failure_and_trace_floor_still_block(self) -> None:
        for metrics in (
            validator.Metrics(num_traces=16_000),
            validator.Metrics(tau=0.0, num_traces=15_999),
            validator.Metrics(tau=0.0, num_traces=16_000, overall_pass=False),
        ):
            with self.subTest(metrics=metrics):
                status, _ = self.evaluate(metrics)
                assert status == 1


if __name__ == "__main__":
    unittest.main()
