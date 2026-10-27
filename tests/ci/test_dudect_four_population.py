"""The four-exception supplement cannot cross the distributed-population boundary."""

# ruff: noqa: PT009, E402
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests/dudect_analysis"), str(ROOT / "tests/constant_time")]
from dudect_sparse import BASE_CONTRACT, BASE_NUMERICAL
from sparse_four import augment


class PopulationTests(unittest.TestCase):
    def test_replacement_crops_never_read_original_histogram(self):
        row = {
            "profile": "pr",
            "binding": {"contract_sha256": BASE_CONTRACT, "numerical_sha256": BASE_NUMERICAL},
        }
        tests = [
            {"id": i, "eligible": True, "p": 1.0}
            if i in (0, 101)
            else {"id": i, "eligible": False, "reason": "degenerate_variance"}
            for i in range(102)
        ]
        prefix = Mock()
        effective, receipts = augment(row, tests, prefix, excluded=range(1, 101))
        self.assertEqual(effective, tests)
        self.assertEqual(receipts, [])
        prefix.check_row.assert_called_once_with(row)
        prefix.endpoints.assert_not_called()
        prefix.selected.assert_not_called()


if __name__ == "__main__":
    unittest.main()
