# Use the standard-library unittest runner inside the Nix package.
# ruff: noqa: PT009, PT027
from __future__ import annotations

import json
import math
import time
import unittest
from fractions import Fraction
from pathlib import Path

from enclosed_tail import ALPHA, classify, enclose


class EnclosureTests(unittest.TestCase):
    def test_reviewed_threshold_grid(self):
        fixture = json.loads(Path(__file__).with_name("threshold-reference.json").read_text())
        self.assertEqual(len(fixture["rows"]), 63)
        for row in fixture["rows"]:
            with self.subTest(t=row["t_hex"], degrees=row["degrees_hex"]):
                result = enclose(float.fromhex(row["t_hex"]), float.fromhex(row["degrees_hex"]))
                self.assertEqual(
                    result["decision"], "detected" if row["reference_detection"] else "nondetected"
                )
                bounds = result["attempts"][-1]
                reference = Fraction(row["reference_probability"])
                self.assertLessEqual(Fraction(*bounds["lower"]), reference)
                self.assertGreaterEqual(Fraction(*bounds["upper"]), reference)

    def test_strict_threshold_and_equality(self):
        self.assertEqual(classify(ALPHA / 2, ALPHA * 3 / 4), "detected")
        self.assertEqual(classify(ALPHA, ALPHA), "nondetected")
        self.assertEqual(classify(ALPHA / 2, ALPHA), "numerically_unresolved")
        self.assertEqual(classify(ALPHA / 2, ALPHA * 2), "numerically_unresolved")

    def test_zero(self):
        r = enclose(0.0, 10000.0)
        self.assertEqual(r["decision"], "nondetected")
        self.assertEqual(r["attempts"][-1]["lower"], [1, 1])

    def test_sign_invariance(self):
        a, b = enclose(5.0, 20000.0), enclose(-5.0, 20000.0)
        self.assertEqual(a["attempts"], b["attempts"])

    def test_known_cauchy_value_enclosed(self):
        r = enclose(1.0, 1.0)
        bounds = r["attempts"][-1]
        self.assertLessEqual(Fraction(*bounds["lower"]), Fraction(1, 2))
        self.assertGreaterEqual(Fraction(*bounds["upper"]), Fraction(1, 2))

    def test_precision_exhaustion_not_nondetection(self):
        r = enclose(4.999822847446288, 10000.5, precisions=(64,))
        self.assertEqual(r["decision"], "numerically_unresolved")
        self.assertEqual(r["reason"], "precision_limit")

    def test_refinement_resolves_counterexample(self):
        r = enclose(4.999822847446288, 10000.5, precisions=(64, 128))
        self.assertEqual(r["decision"], "nondetected")
        self.assertEqual(r["attempts"][-1]["bits"], 128)

    def test_large_control_uses_direct_tail(self):
        r = enclose(240.60158650304595, 61024.03333139779)
        self.assertEqual(r["decision"], "detected")
        self.assertEqual(r["attempts"][-1]["method"], "direct")
        self.assertGreater(Fraction(*r["attempts"][-1]["upper"]), 0)

    def test_expired_deadline(self):
        r = enclose(1.0, 1.0, deadline=time.monotonic() - 1)
        self.assertEqual(r["decision"], "numerically_unresolved")
        self.assertEqual(r["attempts"], [])

    def test_invalid_input(self):
        for t, df in ((math.nan, 1.0), (math.inf, 1.0), (1.0, math.inf), (1.0, 0.0), (1.0, -1.0)):
            with self.subTest(t=t, df=df), self.assertRaises(ValueError):
                enclose(t, df)

    def test_large_and_small_t(self):
        r = enclose(1e100, 10000.0)
        self.assertEqual(r["decision"], "detected")
        self.assertLessEqual(r["attempts"][-1]["upper"][1].bit_length(), 129)
        self.assertEqual(enclose(1e-100, 10000.0)["decision"], "nondetected")

    def test_invalid_enclosure(self):
        with self.assertRaises(ValueError):
            classify(Fraction(1), Fraction(0))


if __name__ == "__main__":
    unittest.main()
