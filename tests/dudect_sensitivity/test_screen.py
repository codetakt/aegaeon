# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009, PT027
import copy
import json
import unittest
from screen import evaluate, check_receipts


class ScreenTests(unittest.TestCase):
    def history(self):
        return [
            {
                "look": i,
                "collection_complete": i == 8,
                "raw_class_counts": [500000, 500000],
                "numerically_unresolved_ever": [],
                "tests": [{"id": j, "eligible": True} for j in range(102)],
                "detected_now": [1] if i == 1 else [],
                "detected_ever": [1],
            }
            for i in range(1, 9)
        ]

    def result(self, h, scope="early"):
        return evaluate(h, scope, {"requirement_satisfied": False})

    def test_signal_success(self):
        self.assertTrue(self.result(self.history())["passed"])

    def test_raw_floor_cannot_be_overridden(self):
        h = self.history()
        h[-1]["raw_class_counts"][0] = 199999
        self.assertFalse(self.result(h)["passed"])

    def test_numerical_failure_cannot_be_overridden(self):
        h = self.history()
        h[0]["numerically_unresolved_ever"] = [{"id": 2}]
        self.assertFalse(self.result(h)["passed"])

    def test_incomplete_collection(self):
        h = self.history()
        h[-1]["collection_complete"] = False
        self.assertFalse(self.result(h)["passed"])

    def test_missing_look(self):
        self.assertFalse(self.result(self.history()[1:])["passed"])

    def test_bad_inventory(self):
        h = self.history()
        h[-1]["tests"].pop()
        self.assertFalse(self.result(h)["passed"])

    def test_final_ineligible(self):
        h = self.history()
        h[-1]["tests"][1]["eligible"] = False
        self.assertFalse(self.result(h)["passed"])

    def test_other_statistic_does_not_substitute(self):
        for j in (0, 2, 101):
            h = self.history()
            h[0]["detected_now"] = [j]
            h[-1]["detected_ever"] = [j]
            self.assertFalse(self.result(h)["passed"])

    def test_late_requires_final_detection(self):
        self.assertFalse(self.result(self.history(), "late")["passed"])

    def test_late_presignal_rejects(self):
        h = self.history()
        h[-1]["detected_now"] = [1]
        self.assertFalse(self.result(h, "late")["passed"])
        h[0]["detected_now"] = []
        self.assertTrue(self.result(h, "late")["passed"])

    def test_lost_detection(self):
        h = self.history()
        h[-1]["detected_ever"] = []
        self.assertFalse(self.result(h)["passed"])

    def test_zero_keeps_actual_role(self):
        self.assertFalse(self.result(self.history(), "zero")["passed"])

    def test_receipt_labels_and_pilot(self):
        frames = [bytes([0, 1]) * 32768] * 17
        receipts = [
            {
                "batch": b,
                "samples": 65536,
                "signal_samples": 32768 if 1 <= b <= 8 else 0,
                "scope": 1,
            }
            for b in range(17)
        ]

        def text(rs):
            return (
                "\n".join("HMAC_SIGNAL_FRAME " + json.dumps(r) for r in rs)
                + '\nHMAC_SIGNAL_COMPLETE {"frames":17,"prepared":1114112}'
            )

        check_receipts(text(receipts), "early", frames)
        for b in (0, 1, 8, 9, 16):
            changed = copy.deepcopy(receipts)
            changed[b]["signal_samples"] += 1
            with self.assertRaises(ValueError):
                check_receipts(text(changed), "early", frames)
        with self.assertRaises(ValueError):
            check_receipts(text(receipts[:-1]), "early", frames)


if __name__ == "__main__":
    unittest.main()
