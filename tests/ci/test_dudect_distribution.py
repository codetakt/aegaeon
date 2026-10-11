# ruff: noqa: PT009 - unittest assertions remain active under Python -O
"""Known ordered distributions expose drift without an inference or filtering rule."""

from __future__ import annotations

import unittest

from dudect_distribution import describe, summarize_context, summarize_distribution


class DistributionTests(unittest.TestCase):
    def test_order_statistics_use_integer_ranks_and_include_ties(self):
        self.assertEqual(
            describe(list(reversed(range(100)))),
            {
                "count": 100,
                "order_statistics": {"min": 0, "p05": 5, "median": 50, "p95": 95, "max": 99},
            },
        )
        self.assertEqual(describe([]), {"count": 0, "order_statistics": None})
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
            self.assertEqual(result["classes"][1], {"count": 0, "order_statistics": None})
            self.assertEqual(sum(c["count"] for c in result["classes"]), max(0, len(deltas) - 10))

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
