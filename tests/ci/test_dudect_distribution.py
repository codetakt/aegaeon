# ruff: noqa: PT009 - unittest assertions remain active under Python -O
"""Known ordered distributions expose drift without an inference or filtering rule."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))

from dudect_distribution import describe, summarize_context, summarize_distribution


class DistributionTests(unittest.TestCase):
    def test_order_statistics_use_integer_ranks_and_include_ties(self):
        self.assertEqual(
            describe(list(reversed(range(100)))),
            {
                "count": 100,
                "sum_ticks": 4950,
                "sum_squared_ticks": 328350,
                "order_statistics": {"min": 0, "p05": 5, "median": 50, "p95": 95, "max": 99},
            },
        )
        self.assertEqual(
            describe([]),
            {"count": 0, "sum_ticks": 0, "sum_squared_ticks": 0, "order_statistics": None},
        )
        self.assertEqual(
            describe([7] * 21)["order_statistics"],
            dict.fromkeys(("min", "p05", "median", "p95", "max"), 7),
        )

    def test_native_indices_keep_zero_and_negative_counts_with_original_labels(self):
        # The ten excluded leading durations must not contaminate distributions.
        deltas = (9999,) * 10 + (-1, 0, 2, 3, 4, 5, 6, 7)
        labels = bytes([0] * 10 + [0, 1] * 4 + [1])
        result = summarize_distribution(deltas, labels)
        self.assertEqual(result["indices"], [10, 18])
        self.assertEqual(result["negative_deltas"], 1)
        self.assertEqual([r["count"] for r in result["classes"]], [3, 4])
        self.assertEqual(
            result["classes"][0]["order_statistics"],
            {"min": 2, "p05": 2, "median": 4, "p95": 6, "max": 6},
        )
        self.assertEqual(result["classes"][1]["order_statistics"]["min"], 0)
        self.assertEqual(
            [b["indices"] for b in result["blocks"]], [[i, i + 1] for i in range(10, 18)]
        )
        self.assertIsNone(result["blocks"][0]["classes"][0]["order_statistics"])

    def test_late_shift_is_visible_without_dropping_any_block(self):
        result = summarize_distribution((100,) * 18 + (200,) * 8, bytes([0, 1] * 14))
        self.assertEqual(result["negative_deltas"], 0)
        for group in (0, 1):
            self.assertEqual(result["classes"][group]["count"], 8)
            self.assertEqual(
                [b["classes"][group]["order_statistics"]["median"] for b in result["blocks"]],
                [100] * 4 + [200] * 4,
            )

    def test_uneven_blocks_partition_all_admitted_indices(self):
        result = summarize_distribution(tuple(range(65535)), bytes([0, 1] * 32768))
        self.assertEqual(
            [b["indices"] for b in result["blocks"]],
            [[10 + j * 65525 // 8, 10 + (j + 1) * 65525 // 8] for j in range(8)],
        )
        self.assertEqual([c["count"] for c in result["classes"]], [32763, 32762])
        self.assertEqual(sum(c["count"] for b in result["blocks"] for c in b["classes"]), 65525)

    def test_missing_class_and_empty_native_range_are_explicit(self):
        for deltas in ((5,), (5,) * 19):
            result = summarize_distribution(deltas, bytes(len(deltas) + 1))
            self.assertEqual(
                result["classes"][1],
                {"count": 0, "sum_ticks": 0, "sum_squared_ticks": 0, "order_statistics": None},
            )
            self.assertEqual(sum(c["count"] for c in result["classes"]), max(0, len(deltas) - 10))

    def test_exact_moments_preserve_large_integer_variance(self):
        # Adjacent values above float precision still have sample variance 1.
        center = 2**62
        result = describe([center - 1, center, center + 1])
        self.assertEqual(result["sum_ticks"], 3 * center)
        self.assertEqual(result["sum_squared_ticks"], 3 * center * center + 2)
        numerator = result["count"] * result["sum_squared_ticks"] - result["sum_ticks"] ** 2
        self.assertEqual(numerator, 6)

    def test_preceding_labels_cross_blocks_and_discarded_durations(self):
        # Eight one-sample blocks; index 9 is excluded from the duration summary
        # but is still the predecessor of index 10. A negative duration is not
        # removed from the label sequence, and the unused final label is ignored.
        deltas = (999,) * 10 + (10, -1, 20, 30, 40, 50, 60, 70)
        labels = bytes([0] * 9 + [1] + [0, 1, 0, 0, 1, 1, 0, 1] + [1])
        result = summarize_distribution(deltas, labels)
        expected = [[30], [40, 70], [10, 20, 60], [50]]  # 00, 01, 10, 11
        for pair, values in enumerate(expected):
            row = result["label_transitions"][pair]
            self.assertEqual(row["count"], len(values))
            self.assertEqual(row["sum_ticks"], sum(values))
            self.assertEqual(row["sum_squared_ticks"], sum(v * v for v in values))
        for block, pair in zip(result["blocks"], (2, None, 2, 0, 1, 3, 2, 1), strict=True):
            self.assertEqual(
                [row["count"] for row in block["label_transitions"]],
                [int(index == pair) for index in range(4)],
            )
        for part in [result, *result["blocks"]]:
            for current in (0, 1):
                for key in ("count", "sum_ticks", "sum_squared_ticks"):
                    self.assertEqual(
                        part["classes"][current][key],
                        sum(
                            part["label_transitions"][pair][key] for pair in (current, current + 2)
                        ),
                    )

    def test_transition_history_resets_at_each_batch(self):
        deltas = (3,) * 12
        first = summarize_distribution(deltas, bytes([1] * 13))
        second = summarize_distribution(deltas, bytes([0] * 13))
        self.assertEqual([x["count"] for x in first["label_transitions"]], [0, 0, 0, 2])
        self.assertEqual([x["count"] for x in second["label_transitions"]], [2, 0, 0, 0])

    def test_context_preserves_gap_unknown_cpu_and_counter_units(self):
        values = (1, 65536, 100, 250, 2**64 - 1, 3, 1, 3, 4, 7, 8, 12, 0, 5, 9, 15, 10, 17)
        result = summarize_context(values, 60)
        self.assertEqual(result["monotonic_ns"], [100, 250])
        self.assertEqual(result["duration_ns"], 150)
        self.assertEqual(result["gap_before_ns"], 40)
        self.assertEqual(result["cpus"], [None, 3])
        self.assertEqual(list(result["resource_deltas"].values()), [2, 3, 4, 5, 6, 7])
        self.assertIsNone(summarize_context(values, None)["gap_before_ns"])


if __name__ == "__main__":
    unittest.main()
