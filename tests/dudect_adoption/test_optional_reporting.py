# unittest checks must run without pytest and under Python -O.
# ruff: noqa: PT009, PT027
"""Reporting and deadline-order regressions, without new physical measurements."""

from __future__ import annotations

import copy
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/validation" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPORT = load("dudect_replay_report")
RUNNER = load("run_dudect_operations_tests")


def assessment():
    return {
        "qualification_passed": True,
        "raw_floor_met": True,
        "evidence_valid": True,
        "final_raw0_101_eligible": True,
        "all_final_statistics_eligible": True,
        "execution_valid": True,
        "effective_result": {"requirement_satisfied": True},
        "statistical_outcome": "budget_nondetection",
    }


def proofs():
    result = []
    for look in range(1, 9):
        row = {
            "case": "ct_eq_32",
            "look": look,
            "tests": [{"id": i, "detected": False} for i in range(102)],
        }
        result.append(
            {
                "effective": copy.deepcopy(row),
                "original_sparse_proof": {"history": {"original": row}},
            }
        )
    return result


class ReportingTests(unittest.TestCase):
    def test_raw_floor_is_required_for_budget_nondetection(self):
        value = assessment()
        value["raw_floor_met"] = False
        value["qualification_passed"] = False
        value["effective_result"]["requirement_satisfied"] = False
        before = copy.deepcopy(value)
        result = REPORT.axes(value)
        self.assertEqual(result["observation"], "not_evaluable")
        self.assertEqual(result["legacy_statistical_outcome"], "budget_nondetection")
        self.assertFalse(result["qualification_passed"])
        self.assertEqual(value, before)

    def test_count_numeric_execution_limits_cannot_become_nondetection(self):
        for field in (
            "raw_floor_met",
            "final_raw0_101_eligible",
            "all_final_statistics_eligible",
            "evidence_valid",
            "execution_valid",
        ):
            with self.subTest(field=field):
                value = assessment()
                value[field] = False
                self.assertEqual(REPORT.axes(value)["observation"], "not_evaluable")

    def test_detected_is_retained_even_when_budget_fails(self):
        value = assessment()
        value.update(
            statistical_outcome="detected", raw_floor_met=False, qualification_passed=False
        )
        value["effective_result"]["requirement_satisfied"] = False
        self.assertEqual(REPORT.axes(value)["observation"], "detected")
        self.assertFalse(REPORT.axes(value)["qualification_passed"])

    def test_unknown_or_ambiguous_axes_rejected(self):
        for field, bad in (("statistical_outcome", "passed"), ("raw_floor_met", 1)):
            value = assessment()
            value[field] = bad
            with self.assertRaises(ValueError):
                REPORT.axes(value)
        value = assessment()
        value["effective_result"]["requirement_satisfied"] = False
        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            REPORT.axes(value)

    def changes(self, values, role="protected_input_observation"):
        return REPORT.detection_changes(values, "nix/ct_eq_32", role, lambda t: t["detected"])

    def test_original_only_early_crop_detection_remains_visible(self):
        values = proofs()
        values[1]["original_sparse_proof"]["history"]["original"]["tests"][7]["detected"] = True
        result = self.changes(values)
        self.assertEqual(result["nondetection_role_original_only_crops"], [[2, 7]])
        self.assertFalse(result["original_gate_OR_applied"])

    def test_characterization_and_non_crop_differences_are_separate(self):
        values = proofs()
        for i in (0, 7, 101):
            values[0]["original_sparse_proof"]["history"]["original"]["tests"][i]["detected"] = True
        result = self.changes(values, "public_fixture_characterization")
        self.assertEqual(result["original_only_crop_detections"], [[1, 7]])
        self.assertEqual(result["nondetection_role_original_only_crops"], [])
        self.assertEqual(len(result["original_only_statistic_looks"]), 3)

    def test_matched_detection_not_reported_as_removed(self):
        values = proofs()
        values[2]["effective"]["tests"][1]["detected"] = True
        values[2]["original_sparse_proof"]["history"]["original"]["tests"][1]["detected"] = True
        self.assertEqual(self.changes(values)["original_only_statistic_looks"], [])

    def test_missing_reordered_case_or_statistic_history_rejected(self):
        for mutation in (
            lambda p: p.pop(),
            lambda p: p.reverse(),
            lambda p: p[0]["effective"].update(case="hmac_sha256"),
            lambda p: p[0]["effective"]["tests"].pop(),
        ):
            values = proofs()
            mutation(values)
            with self.assertRaises(ValueError):
                self.changes(values)

    def test_snapshot_rejects_symlink_fifo_and_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "input"
            path.write_bytes(b"data")
            self.assertEqual(REPORT.snapshot(root)["input"]["sha256"], REPORT.digest(b"data"))
            with (
                patch.object(REPORT, "MAX_BYTES", 3),
                self.assertRaisesRegex(ValueError, "size limit"),
            ):
                REPORT.snapshot(root)
            link = root / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "Non-regular"):
                REPORT.snapshot(root)
            link.unlink()
            os.mkfifo(link)
            with self.assertRaisesRegex(ValueError, "Non-regular"):
                REPORT.snapshot(root)

    def test_age_dependency_is_explicit_and_hash_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            age, keygen = root / "age", root / "age-keygen"
            for path in (age, keygen):
                path.write_bytes(b"fixture")
                path.chmod(0o700)
            sha = REPORT.digest(b"fixture")
            self.assertEqual(RUNNER.age_dependency(age, sha, sha), age.resolve())
            for args in ((age, "0" * 64, sha), (age, sha, "0" * 64), (Path("age"), sha, sha)):
                with self.assertRaises(ValueError):
                    RUNNER.age_dependency(*args)
            keygen.unlink()
            with self.assertRaises(ValueError):
                RUNNER.age_dependency(age, sha, sha)


if __name__ == "__main__":
    unittest.main()
