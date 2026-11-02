# Use the standard-library unittest runner inside the Nix package.
# ruff: noqa: PT009
from __future__ import annotations

import random
import unittest
from collections import Counter

from analysis_runtime import CompactPrefix
from dudect_sparse_replay import Prefix


class CompactTests(unittest.TestCase):
    def test_original_index_and_crop_equivalence(self):
        rng = random.Random(0x791986)  # noqa: S311 -- deterministic arithmetic fixture
        for size in (0, 3, 10001, 65525):
            hist = [
                Counter(rng.randrange(max(1, size // 2)) for _ in range(size)),
                Counter({i: 1 + (i % 7) for i in range(size)}),
            ]
            old, new = Prefix(), CompactPrefix()
            old.histograms = new.histograms = hist
            self.assertEqual(
                [(v, list(c)) for v, c in old.indexed()], [(v, list(c)) for v, c in new.indexed()]
            )
            for cutoff in (-1, 0, 2, 123, size):
                counts = [sum(c for t, c in h.items() if t <= cutoff) for h in hist]
                row = {
                    "pilot": {"cutoffs": [cutoff] * 100},
                    "statistics": [[sum(h.values()) for h in hist]] + [counts] * 100,
                }
                for method in ("endpoints", "selected"):
                    self.assertEqual(getattr(old, method)(row, 1), getattr(new, method)(row, 1))


if __name__ == "__main__":
    unittest.main()
