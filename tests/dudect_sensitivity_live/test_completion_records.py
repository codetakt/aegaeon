# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I002, PT027
import copy
import unittest

import analysis_contract  # noqa: F401 -- install frozen native-verifier import path
from receipts import N, verify_completion_records


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.targets = [
            "ct_eq_32",
            "ct_eq_64",
            "ct_eq_128",
            "sha256",
            "hmac_sha256",
            "hmac_sha256_key",
        ]
        self.frames = [
            {"target": t, "batch": b, "samples": N, "profile": 0}
            for t in (0, 3, 4, 5, 1, 2)
            for b in range(17)
        ]
        self.complete = [
            {"target": t, "frames": 17, "prepared": 17 * N, "callbacks": 17 * N} for t in range(6)
        ]

    def test_full_provider_uses_two_distinct_orders(self):
        verify_completion_records(self.targets, "zero", self.frames, self.complete)

    def test_missing_or_duplicate_target_refused(self):
        for records in (self.complete[:-1], self.complete + [self.complete[-1]]):  # noqa: RUF005 -- retain the measured sequence construction
            with self.assertRaises(ValueError):
                verify_completion_records(self.targets, "zero", self.frames, records)

    def test_missing_or_reordered_frame_refused(self):
        for frames in (self.frames[:-1], self.frames[17:] + self.frames[:17]):
            with self.assertRaises(ValueError):
                verify_completion_records(self.targets, "zero", frames, self.complete)

    def test_wrong_callback_preparation_or_frame_count_refused(self):
        for field in ("frames", "prepared", "callbacks"):
            records = copy.deepcopy(self.complete)
            records[3][field] -= 1
            with self.assertRaises(ValueError):
                verify_completion_records(self.targets, "zero", self.frames, records)

    def test_completion_execution_order_is_not_native_order(self):
        records = [self.complete[t] for t in (0, 3, 4, 5, 1, 2)]
        with self.assertRaises(ValueError):
            verify_completion_records(self.targets, "zero", self.frames, records)

    def test_single_ct64_preserves_appended_identity(self):
        verify_completion_records(["ct_eq_64"], "zero", self.frames[17:34], self.complete[3:4])
        with self.assertRaises(ValueError):
            verify_completion_records(["ct_eq_64"], "zero", self.frames[:17], self.complete[:1])


if __name__ == "__main__":
    unittest.main()
