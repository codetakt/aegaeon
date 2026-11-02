# Use independent index-allocation enumeration, not the grouped kernel formula.
# ruff: noqa: PT009, PT027
from __future__ import annotations

import copy
import itertools
import json
import unittest
from collections import Counter
from fractions import Fraction

from analysis_contract import History, assess, significant
from dudect_sparse import REVIEWED, falling
from sparse_four import exact_tail, supplement
from test_analysis import advance, tests

DEGENERATE = {"id": 1, "eligible": False, "reason": "degenerate_variance"}
HIST = [{609: 209465}, {583: 4, 609: 209625}]


class FourTests(unittest.TestCase):
    def result(self, hist=None, index=1, center=600.0, original=None, config=None):
        return supplement(
            original or DEGENERATE,
            HIST if hist is None else hist,
            index,
            center,
            json.loads(REVIEWED) if config is None else config,
        )

    def test_independent_all_index_allocations(self):
        for values in (
            [10] * 5 + [8] * 4,
            [10] * 5 + [7, 8, 12, 13],
            [10] * 5 + [8, 8, 12, 12],
            [0, 0, 1, 1],
            [3] * 5,
        ):
            for n0 in range(1, len(values)):
                assignments = list(itertools.combinations(range(len(values)), n0))
                deltas = [
                    abs(
                        Fraction(sum(values[i] for i in a), n0)
                        - Fraction(
                            sum(values[i] for i in range(len(values)) if i not in a),
                            len(values) - n0,
                        )
                    )
                    for a in assignments
                ]
                seen = set()
                for assignment, observed in zip(assignments, deltas, strict=True):
                    hist = [
                        Counter(values[i] for i in assignment),
                        Counter(values[i] for i in range(len(values)) if i not in assignment),
                    ]
                    key = tuple(sorted(hist[0].items()))
                    if key in seen:
                        continue
                    seen.add(key)
                    actual = exact_tail(hist, {v: Fraction(v) for v in values})
                    expected = Fraction(sum(d >= observed for d in deltas), len(deltas))
                    self.assertEqual(Fraction(*actual["p_exact"]), expected)
                    self.assertLessEqual(actual["allocation_states"], 16)

    def test_retained_four_value_and_class_exchange(self):
        result = self.result()
        self.assertTrue(result["applied"])
        self.assertEqual(
            result["decision"]["p_exact"], [160669154419514236441, 1285370456524178743251]
        )
        self.assertEqual(
            result["decision"]["p_exact"], self.result(HIST[::-1])["decision"]["p_exact"]
        )
        self.assertFalse(significant(result["decision"]))

    def test_uniform_four_bound_insufficient_and_count_boundary(self):
        alpha = Fraction(*json.loads(REVIEWED)["alpha_ratio"])
        self.assertLess(Fraction(falling(10001, 4), falling(1048400, 4)), alpha)
        # Adjacent real count values straddle the exact lower-bound condition.
        total = 1048400
        low, high = 10001, total // 2
        while low + 1 < high:
            middle = (low + high) // 2
            if Fraction(falling(middle, 4), falling(total, 4)) >= alpha:
                high = middle
            else:
                low = middle
        for n, applied in ((low, False), (high, True)):
            result = self.result([{609: n}, {609: total - n - 4, 583: 4}])
            self.assertEqual(result["applied"], applied)
        self.assertEqual(
            self.result([{609: 10000}, {609: 20000, 583: 4}])["reason"], "insufficient_count"
        )

    def test_other_domains_and_valid_decisions_preserved(self):
        for r in (0, 1, 2, 3, 5, 24):
            h = [{609: 20000}, {609: 20000}]
            if r:
                h[1][583] = r
            self.assertFalse(self.result(h)["applied"])
        for original in (
            {**DEGENERATE, "eligible": True, "p": 0.0},
            {**DEGENERATE, "reason": "insufficient_count"},
        ):
            self.assertEqual(self.result(original=original)["reason"], "base_result_preserved")
        for key, value in (
            ("profile", "periodic"),
            ("deadline_seconds", 901),
            ("alpha_ratio", [1, 100]),
            ("minimum_class_count", 10000),
            ("base_numerical_sha256", "0" * 64),
        ):
            config = json.loads(REVIEWED)
            config[key] = value
            self.assertEqual(self.result(config=config)["reason"], "unreviewed_configuration")

    def test_invalid_proof_and_transform_boundaries(self):
        for hist in ([{609: 0}, {583: 4, 609: 20000}], [{609: 1048400}, {583: 4, 609: 20000}]):
            with self.assertRaises(ValueError):
                self.result(hist)
        self.assertEqual(
            self.result([{2**53: 20000}, {2**53: 20000, 1: 4}])["reason"],
            "unsupported_tick_representation",
        )
        self.assertEqual(self.result(index=101, center=596.0)["reason"], "transform_collision")
        self.assertTrue(self.result(index=101)["applied"])

    def test_same_look_history_and_required_control_preserved(self):
        h = History()
        items = tests()
        items[1] = self.result()["decision"]
        items[8] = {"id": 8, "eligible": True, "p": 0.0}
        rows = [advance(h, items, 1, "control_variance_shift")]
        rows += [advance(h, tests(), i, "control_variance_shift") for i in range(2, 9)]
        self.assertEqual(rows[-1]["detected_ever"], [8])
        self.assertEqual(
            assess("nix/control_variance_shift", "measurement_positive_control", rows)["failure"],
            "required_statistic_101_not_detected",
        )
        before = copy.deepcopy(DEGENERATE)
        self.result(original=DEGENERATE)
        self.assertEqual(DEGENERATE, before)


if __name__ == "__main__":
    unittest.main()
