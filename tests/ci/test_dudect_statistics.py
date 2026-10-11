# ruff: noqa: PT027 - unittest discovery has no pytest dependency
# ruff: noqa: PT009 - unittest assertions remain active with Python optimization
"""Independent numerical references and fail-closed observation admission."""

from __future__ import annotations

import copy
import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_process import load_json
from dudect_results import (
    ALPHA,
    BATCH_SIZE,
    LEGACY_CASES,
    NONDETECTION,
    PROFILES,
    CaseAdmission,
    student_tail,
    validate_report,
)


def observation(name="compare", profile="pr", look=1):
    batches = PROFILES[profile][0][look - 1]
    total = batches * (BATCH_SIZE - 11)
    n0, n1 = total // 2, total - total // 2
    return {
        "schema_version": 2,
        "case": name,
        "profile": profile,
        "batch_size": BATCH_SIZE,
        "batches": batches,
        "look": look,
        "executed": (batches + 1) * BATCH_SIZE,
        "warmup": BATCH_SIZE,
        "rejected": 0,
        "pilot": {"count": 65525, "center": 100, "cutoffs": [200] * 100},
        "statistics": [[n0, n1, 100, 100, (n0 - 1) * 9, (n1 - 1) * 9] for _ in range(102)],
    }


def complete_report(profile="pr"):
    return {
        "schema_version": 2,
        "suite": "legacy",
        "profile": profile,
        "outcome": NONDETECTION,
        "cases": {
            name: [
                observation(name, profile, look) for look in range(1, len(PROFILES[profile][0]) + 1)
            ]
            for name in LEGACY_CASES
        },
    }


class DudectStatisticsTests(unittest.TestCase):
    def test_student_tail_against_closed_form_cauchy(self):
        for t in (0, 0.01, 0.5, 1, 2, 10, 100, 10000):
            expected = 2 * math.atan2(1, t) / math.pi
            self.assertAlmostEqual(student_tail(t, 1), expected, delta=2e-13)
            self.assertEqual(student_tail(t, 1), student_tail(-t, 1))

    def test_student_tail_against_degree_two_closed_form(self):
        for t in (0, 0.01, 0.5, 1, 2, 10, 100):
            expected = 1 - t / math.sqrt(t * t + 2)
            self.assertAlmostEqual(student_tail(t, 2), expected, delta=2e-13)

    def test_fractional_degrees_and_large_sample_reference(self):
        self.assertGreater(student_tail(3, 4.5), student_tail(3, 5))
        for t in (0.5, 1, 2, 4.870336775915474, 10):
            self.assertAlmostEqual(
                student_tail(t, 1_000_000), math.erfc(t / math.sqrt(2)), delta=1e-6
            )
        self.assertAlmostEqual(
            student_tail(2.2281388519649385, 10), 0.05000000000180864, delta=1e-14
        )
        self.assertAlmostEqual(ALPHA, 0.01 / 8976)

    def test_fractional_tail_against_independent_scipy_references(self):
        # SciPy 1.18.0, two-sided t.sf; no SciPy dependency at runtime.
        for degrees, expected in (
            (3.5, 0.011459317352566264),
            (100.25, 4.172745709157673e-6),
            (6400000, 1.1160090427322038e-6),
        ):
            self.assertAlmostEqual(student_tail(4.87, degrees), expected, delta=expected * 1e-8)

    def test_both_complete_profiles_are_admitted(self):
        for profile in PROFILES:
            validate_report(complete_report(profile))

    def test_warmup_legacy_reports_and_missing_cases_are_rejected(self):
        for value in ({"state": 1, "p": 0.999, "num_traces": 20000}, {}, []):
            with self.assertRaises(ValueError):
                validate_report(value)
        report = complete_report()
        report["cases"].pop("hmac")
        with self.assertRaisesRegex(ValueError, "inventory"):
            validate_report(report)

    def test_an_early_failure_cannot_be_hidden_by_later_success(self):
        report = complete_report()
        report["cases"]["hmac"][0]["statistics"][1][2] = 1000
        with self.assertRaisesRegex(ValueError, "leakage_detected"):
            validate_report(report)

    def test_raw_counts_cannot_replace_a_sparse_or_degenerate_crop(self):
        for kind in ("count", "variance"):
            report = complete_report()
            for row in report["cases"]["hmac"]:
                if kind == "count":
                    row["statistics"][1][0] = 1
                else:
                    row["statistics"][1][4] = 0
            with self.assertRaisesRegex(ValueError, "inconclusive"):
                validate_report(report)

    def test_missing_reordered_repeated_and_extra_looks_are_rejected(self):
        for indexes in (
            [1, 2, 3, 4, 5, 6],
            [0, 2, 1, 3, 4, 5, 6],
            [0, 0, 1, 2, 3, 4, 5, 6],
            [*range(7), 6],
        ):
            report = complete_report()
            rows = report["cases"]["compare"]
            report["cases"]["compare"] = [rows[i] for i in indexes]
            with self.assertRaises(ValueError):
                validate_report(report)

    def test_counter_tampering_and_identity_substitution_are_rejected(self):
        for field, value in (
            ("executed", 1),
            ("warmup", 0),
            ("case", "rsa"),
            ("profile", "periodic"),
            ("schema_version", True),
            ("rejected", -1),
            ("batches", 0),
        ):
            data = observation()
            data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CaseAdmission("compare", "pr").admit(data)

    def test_nonfinite_negative_and_boolean_statistics_are_rejected(self):
        for index, value in ((0, True), (0, 1.5), (2, float("nan")), (3, float("inf")), (4, -1)):
            data = observation()
            data["statistics"][0][index] = value
            with self.assertRaises(ValueError):
                CaseAdmission("compare", "pr").admit(data)
        for encoded in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValueError):
                load_json(encoded)

    def test_calibration_is_frozen_and_complete(self):
        admission = CaseAdmission("compare", "pr")
        admission.admit(observation())
        for mutation in (
            {"count": 0},
            {"center": float("nan")},
            {"cutoffs": [1]},
            {"cutoffs": [201] * 100},
            {"center": 101},
        ):
            changed = observation(look=2)
            changed["pilot"].update(mutation)
            with self.assertRaises(ValueError):
                admission.admit(changed)

    def test_zero_effect_does_not_end_collection_early(self):
        admission = CaseAdmission("compare", "pr")
        self.assertEqual(admission.admit(observation())["outcome"], "collecting")

    def test_transformed_and_second_order_counts_are_bound_to_raw(self):
        original = observation()
        for index in (1, 101):
            data = copy.deepcopy(original)
            data["statistics"][index][0] += 1
            with self.assertRaises(ValueError):
                CaseAdmission("compare", "pr").admit(data)


if __name__ == "__main__":
    unittest.main()
