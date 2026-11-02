# ruff: noqa: PT009, PT027 - exact arithmetic and evidence rejection tests
"""Independent small-allocation enumeration, bounded rescue and detection retention."""

from __future__ import annotations

import copy
import itertools
import json
import math
import struct
import sys
import unittest
from collections import Counter
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_candidate import ALPHA, CandidateAdmission, significant
from dudect_contract import ObservationError, assess_case
from dudect_sparse import REVIEWED, exact_tail, falling, supplement
from dudect_sparse_contract import check_runtime_contract
from dudect_sparse_replay import Prefix, augment, check_moments
from test_dudect_candidate import observation

CONFIGURATION = json.loads(REVIEWED)
DEGENERATE = {"id": 1, "eligible": False, "reason": "degenerate_variance"}


def histograms(r=3):
    return [{980: 20000 - r, 955: r}, {980: 20000}]


def raw_row(look, rare=3):
    row = observation(look=look, constant=True)
    row["binding"]["contract_sha256"] = check_runtime_contract()
    counts = row["statistics"][0][:2]
    hist = [{980: counts[0] - rare, 955: rare}, {980: counts[1]}]
    row["pilot"]["center"] = 980.0
    row["pilot"]["cutoffs"] = [980] * 100
    for index in range(102):
        stats = [*counts, 0, 0, 0, 0]
        for group, h in enumerate(hist):
            values = {t: float((t - 980) ** 2 if index == 101 else t) for t in h}
            mean = sum(Fraction(values[t]) * n for t, n in h.items()) / counts[group]
            m2 = sum(n * (Fraction(values[t]) - mean) ** 2 for t, n in h.items())
            stats[2 + group], stats[4 + group] = float(mean), float(m2)
            row["support"][index][group] = {
                "count": counts[group],
                "tick_min": min(h),
                "tick_max": max(h),
                "tick_min_count": h[min(h)],
                "tick_max_count": h[max(h)],
                "value_min_hex": min(values.values()).hex(),
                "value_max_hex": max(values.values()).hex(),
            }
        row["statistics"][index] = stats
    return row, hist


def fixture_prefix(row, hist):
    prefix = Prefix()
    prefix.histograms = [Counter(h) for h in hist]
    prefix.batch, prefix.pilot = row["batches"], row["pilot"]
    return prefix


class SparseReplayTests(unittest.TestCase):
    def test_exact_tail_matches_independent_index_enumeration(self):
        distributions = (
            [9] * 5,
            [9] * 5 + [7],
            [9] * 5 + [7, 7],
            [9] * 5 + [7, 8],
            [9] * 5 + [7, 7, 8],
            [9] * 5 + [7, 8, 10],
            [1, 1, 2, 2],
        )
        for values in distributions:
            for n0 in range(1, len(values)):
                allocations = list(itertools.combinations(range(len(values)), n0))
                tails = []
                hs = []
                for indices in allocations:
                    chosen = set(indices)
                    h = [
                        Counter(v for i, v in enumerate(values) if (i in chosen) == group)
                        for group in (True, False)
                    ]
                    hs.append(h)
                    tails.append(
                        abs(
                            Fraction(sum(values[i] for i in indices), n0)
                            - Fraction(
                                sum(values[i] for i in range(len(values)) if i not in chosen),
                                len(values) - n0,
                            )
                        )
                    )
                for h, observed in zip(hs, tails, strict=True):
                    expected = Fraction(sum(t >= observed for t in tails), len(tails))
                    self.assertEqual(
                        Fraction(*exact_tail(h, {v: Fraction(v) for v in values})["p_exact"]),
                        expected,
                    )

    def test_original_failure_p_is_independently_combinatorial(self):
        h = [{980: 69137, 955: 2, 956: 1}, {980: 68884}]
        result = supplement(DEGENERATE, h, 1, 1025.0, CONFIGURATION)
        expected = Fraction(math.comb(69140, 3) + math.comb(68884, 3), math.comb(138024, 3))
        self.assertEqual(Fraction(*result["decision"]["p_exact"]), expected)
        self.assertEqual(expected, Fraction(11672959, 46692369))
        self.assertFalse(significant(result["decision"]))

    def test_reviewed_bound_and_changed_configuration(self):
        bound = Fraction(falling(10001, 3), falling(1048400, 3))
        self.assertGreater(bound, Fraction(ALPHA))
        self.assertLess(Fraction(falling(10001, 4), falling(1048400, 4)), Fraction(ALPHA))
        self.assertLess(Fraction(falling(10001, 3), falling(6421450, 3)), Fraction(ALPHA))
        for key in CONFIGURATION:
            changed = copy.deepcopy(CONFIGURATION)
            changed[key] = None
            self.assertEqual(
                supplement(DEGENERATE, histograms(), 1, 980.0, changed)["reason"],
                "unreviewed_configuration",
            )

    def test_only_two_three_exceptions_and_only_original_degeneracy(self):
        for r in (1, 2, 3, 4, 24, 25):
            self.assertEqual(
                supplement(DEGENERATE, histograms(r), 1, 980.0, CONFIGURATION)["applied"],
                r in (2, 3),
            )
        for original in (
            {"eligible": True, "p": 1e-40},
            {"eligible": True, "p": 0.2},
            {"eligible": False, "reason": "insufficient_count"},
        ):
            before = copy.deepcopy(original)
            self.assertFalse(supplement(original, histograms(), 1, 980.0, CONFIGURATION)["applied"])
            self.assertEqual(original, before)

    def test_count_budget_collision_and_representation(self):
        self.assertEqual(
            supplement(DEGENERATE, [{980: 9998, 955: 2}, {980: 10001}], 1, 980.0, CONFIGURATION)[
                "reason"
            ],
            "insufficient_count",
        )
        with self.assertRaisesRegex(ValueError, "budget"):
            supplement(DEGENERATE, [{980: 1048398, 955: 3}, {980: 10001}], 1, 980.0, CONFIGURATION)
        self.assertEqual(
            supplement(DEGENERATE, histograms(), 101, 967.5, CONFIGURATION)["reason"],
            "transform_collision",
        )
        self.assertEqual(
            supplement(
                DEGENERATE, [{2**53: 19997, 955: 3}, {2**53: 20000}], 1, 980.0, CONFIGURATION
            )["reason"],
            "unsupported_tick_representation",
        )
        for bad in (True, -1, 0, 1.0):
            with self.assertRaises(ValueError):
                supplement(
                    DEGENERATE, [{980: 19997, 955: bad}, {980: 20000}], 1, 980.0, CONFIGURATION
                )

    def test_native_histogram_counts_internal_values_and_moments_are_checked(self):
        row, hist = raw_row(8)
        for group in (0, 1):
            check_moments(hist[group], row, 1, group)
        compact = copy.deepcopy(row)
        compact["support"][1][0]["value_min_hex"] = "0x1.dd8p+9"
        compact["support"][1][0]["value_max_hex"] = "0x1.eap+9"
        check_moments(hist[0], compact, 1, 0)
        for key in ("tick_min_count", "tick_max_count", "count"):
            changed = copy.deepcopy(row)
            changed["support"][1][0][key] += 1
            with self.assertRaisesRegex(ValueError, "support"):
                check_moments(hist[0], changed, 1, 0)
        changed = copy.deepcopy(row)
        changed["statistics"][1][2] += 1
        with self.assertRaisesRegex(ValueError, "mean"):
            check_moments(hist[0], changed, 1, 0)

    def test_full_history_separates_original_and_supplement_and_preserves_controls(self):
        first, _ = raw_row(1)
        baseline = CandidateAdmission("compare", "pr", binding=first["binding"])
        old, new = [], []
        for look in range(1, 9):
            row, hist = raw_row(look)
            original = baseline.admit(row)
            saved = copy.deepcopy(original)
            result = augment(row, original, fixture_prefix(row, hist), False)
            self.assertEqual(original, saved)
            self.assertEqual(result["original"], saved)
            old.append(original)
            new.append(result["effective"])
        self.assertEqual(old[-1]["candidate_statistical_outcome"], "inconclusive")
        self.assertEqual(
            new[-1]["candidate_statistical_outcome"], "no_leakage_detected_within_budget"
        )
        for name in ("control_mean_shift", "control_variance_shift"):
            with self.assertRaises(ObservationError):
                assess_case("legacy/" + name, "measurement_positive_control", new, "pr")

    def test_same_look_and_past_detections_remain_absorbing(self):
        row, hist = raw_row(8)
        # The complete old history is checked in integration; this exercises the merge rule.
        original = {
            "case": "compare",
            "profile": "pr",
            "look": 8,
            "collection_complete": True,
            "raw_class_counts": row["statistics"][0][:2],
            "candidate_statistical_outcome": "inconclusive",
            "tests": [
                {"id": i, "eligible": False, "reason": "degenerate_variance"} for i in range(102)
            ],
        }
        original["tests"][0] = {"id": 0, "eligible": True, "p": 1e-20}
        result = augment(row, original, fixture_prefix(row, hist), False)
        self.assertEqual(result["effective"]["tests"][0], original["tests"][0])
        self.assertEqual(result["effective"]["candidate_statistical_outcome"], "leakage_detected")
        original["tests"][0] = {"id": 0, "eligible": True, "p": 0.5}
        self.assertEqual(
            augment(row, original, fixture_prefix(row, hist), True)["effective"][
                "candidate_statistical_outcome"
            ],
            "leakage_detected",
        )

    def test_frame_prefix_rejects_reordering_truncation_bad_labels_and_counts(self):
        size = 32
        payload = struct.pack(f"<{size}q", *range(0, size * 100, 100)) + bytes([0, 1] * 16)
        prefix = Prefix()
        prefix.push(payload, 0, size)
        self.assertEqual(prefix.histograms, [Counter(), Counter()])
        prefix.push(payload, 1, size)
        first = copy.deepcopy(prefix.histograms)
        self.assertEqual(sum(sum(h.values()) for h in first), size - 11)
        prefix.push(payload, 2, size)
        self.assertEqual(first[0][100] * 2, prefix.histograms[0][100])
        for data, batch in ((payload, 4), (payload[:10], 3), (payload[:-1] + b"\x02", 3)):
            with self.assertRaises(ValueError):
                prefix.push(data, batch, size)


if __name__ == "__main__":
    unittest.main()
