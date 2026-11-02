# Use the standard-library unittest runner inside the Nix package.
# ruff: noqa: PT009, PT027
from __future__ import annotations

import unittest
from unittest.mock import patch

from analysis_contract import History, assess, interval_test, significant
from run_analysis import interrupted


def tests():
    return [
        {
            "id": i,
            "eligible": True,
            "p": 1.0,
            "method": "exact_absolute_mean_permutation_identical_native_support",
        }
        for i in range(102)
    ]


def base(name="hmac_sha256"):
    return {
        "case": name,
        "profile": "pr",
        "look": 1,
        "raw_count": 1000000,
        "raw_class_counts": [500000, 500000],
        "candidate_statistical_outcome": "leakage_detected",
    }


def advance(history, items, look, name="hmac_sha256"):
    return history.append({"look": look, "profile": "pr"}, {**base(name), "look": look}, items)


def interval(decision):
    return {
        "id": 1,
        "eligible": decision != "numerically_unresolved",
        "legacy_p": 0.0,
        "interval": {"decision": decision},
        **({"reason": "numerically_unresolved"} if decision == "numerically_unresolved" else {}),
    }


class AnalysisTests(unittest.TestCase):
    def test_termination_enters_cleanup_exception_path(self):
        with self.assertRaises(InterruptedError):
            interrupted(15, None)

    def test_interval_decision_does_not_use_legacy_p(self):
        self.assertFalse(significant(interval("nondetected")))
        t = interval("detected")
        t["legacy_p"] = 1.0
        self.assertTrue(significant(t))

    def test_common_counterexample(self):
        t = {
            "id": 5,
            "eligible": True,
            "p": 5.83566760035633e-7,
            "t": 4.999822847446288,
            "degrees": 10000.5,
        }
        r = interval_test(t)
        self.assertFalse(significant(r))
        self.assertNotIn("p", r)
        self.assertEqual(t["p"], r["legacy_p"])

    def test_count_ineligible_not_called(self):
        t = {"id": 1, "eligible": False, "reason": "insufficient_count"}
        with patch("analysis_contract.enclose", side_effect=AssertionError):
            self.assertEqual(interval_test(t), t)

    def test_exact_sparse_not_reinterpreted(self):
        t = {"id": 1, "eligible": True, "p": 0.25, "p_exact": [1, 4]}
        with patch("analysis_contract.enclose", side_effect=AssertionError):
            self.assertEqual(interval_test(t), t)

    def test_old_crop_detection_not_orred(self):
        h = History()
        rows = [advance(h, tests(), i) for i in range(1, 9)]
        self.assertEqual(
            rows[-1]["candidate_statistical_outcome"], "no_leakage_detected_within_budget"
        )

    def test_detection_absorbs(self):
        h = History()
        t = tests()
        t[1] = interval("detected")
        advance(h, t, 1)
        for i in range(2, 9):
            r = advance(h, tests(), i)
        self.assertEqual(r["detected_ever"], [1])
        self.assertEqual(r["candidate_statistical_outcome"], "leakage_detected")

    def test_numeric_unresolved_absorbs(self):
        h = History()
        t = tests()
        t[1] = interval("numerically_unresolved")
        rows = [advance(h, t, 1)]
        rows += [advance(h, tests(), i) for i in range(2, 9)]
        self.assertEqual(rows[-1]["candidate_statistical_outcome"], "inconclusive")
        role = assess("nix/hmac_sha256", "protected_input_observation", rows)
        self.assertEqual(role["failure"], "numerically_unresolved")

    def test_count_insufficiency_not_sticky(self):
        h = History()
        t = tests()
        t[1] = {"id": 1, "eligible": False, "reason": "insufficient_count"}
        advance(h, t, 1)
        for i in range(2, 9):
            r = advance(h, tests(), i)
        self.assertEqual(r["candidate_statistical_outcome"], "no_leakage_detected_within_budget")

    def test_positive_requires_101_not_crop(self):
        h = History()
        t = tests()
        t[1] = interval("detected")
        rows = [advance(h, t, i, "control_variance_shift") for i in range(1, 9)]
        self.assertEqual(
            assess("nix/control_variance_shift", "measurement_positive_control", rows)["failure"],
            "required_statistic_101_not_detected",
        )

    def test_positive_earlier_required_statistic_preserved(self):
        h = History()
        t = tests()
        t[101] = {**interval("detected"), "id": 101}
        rows = [advance(h, t, 1, "control_variance_shift")]
        rows += [advance(h, tests(), i, "control_variance_shift") for i in range(2, 9)]
        self.assertTrue(
            assess("nix/control_variance_shift", "measurement_positive_control", rows)[
                "requirement_satisfied"
            ]
        )

    def test_positive_unresolved_not_hidden_by_detection(self):
        h = History()
        t = tests()
        t[101] = {**interval("detected"), "id": 101}
        t[1] = interval("numerically_unresolved")
        rows = [advance(h, t, i, "control_variance_shift") for i in range(1, 9)]
        self.assertFalse(
            assess("nix/control_variance_shift", "measurement_positive_control", rows)[
                "requirement_satisfied"
            ]
        )

    def test_reordered_or_periodic_rejected(self):
        with self.assertRaises(ValueError):
            advance(History(), tests(), 2)
        with self.assertRaises(ValueError):
            History().append({"look": 1, "profile": "periodic"}, base(), tests())


if __name__ == "__main__":
    unittest.main()
