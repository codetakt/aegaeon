# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I002, PT009
import copy
import unittest

from requirements import RECEIPTS, evaluate


def history(detections=((8, 1),)):
    rows, seen = [], set()
    for look in range(1, 9):
        now = sorted(i for k, i in detections if k == look)
        seen.update(now)
        rows.append(
            {
                "case": "ct_eq_32",
                "profile": "pr",
                "look": look,
                "collection_complete": look == 8,
                "raw_class_counts": [500000, 500000],
                "tests": [
                    {
                        "id": i,
                        "eligible": True,
                        "n0": 20000,
                        "n1": 20000,
                        "p": 0.0 if i in now else 1.0,
                    }
                    for i in range(102)
                ],
                "detected_now": now,
                "detected_ever": sorted(seen),
                "numerically_unresolved_ever": [],
            }
        )
    return rows


class RequirementsTests(unittest.TestCase):
    def evaluate(self, rows=None, profile="full", receipts=None, role=False):
        return evaluate(
            "nix/ct_eq_32",
            profile,
            rows if rows is not None else history(),
            {"requirement_satisfied": role},
            receipts or dict.fromkeys(RECEIPTS, True),
        )

    def test_c1_rejects_other_crop(self):
        self.assertIn(
            "required_detection_missing",
            self.evaluate(history(((8, 2),)), "lower_tail")["failures"],
        )

    def test_family_rejects_raw0_and_101(self):
        self.assertIn(
            "required_detection_missing", self.evaluate(history(((8, 0), (8, 101))))["failures"]
        )

    def test_whole_predeclared_family_and_original_result_preserved(self):
        r = self.evaluate(history(((2, 70),)))
        self.assertTrue(r["satisfied"])
        self.assertFalse(r["original_role_result"]["requirement_satisfied"])
        self.assertEqual(r["first_eligible_detection_look"], 2)

    def test_early_detection_cannot_waive_final_count(self):
        rows = history(((2, 70),))
        rows[-1]["tests"][1].update(eligible=False, n1=10000)
        self.assertIn("count_inconclusive", self.evaluate(rows)["failures"])

    def test_eligible_flag_cannot_waive_count(self):
        rows = history()
        rows[-1]["tests"][1]["n0"] = 10000
        self.assertFalse(self.evaluate(rows)["satisfied"])

    def test_raw_floor_and_missing_role_both_reported(self):
        rows = history(())
        rows[-1]["raw_class_counts"][0] = 199999
        r = self.evaluate(rows, "zero")
        self.assertTrue({"count_inconclusive", "original_role_failed"} <= set(r["failures"]))

    def test_unresolved_is_sticky(self):
        rows = history()
        rows[1]["tests"][50].update(eligible=False, reason="numerically_unresolved")
        for r in rows[1:]:
            r["numerically_unresolved_ever"] = [{"look": 2, "statistic": 50}]
        self.assertIn("numerically_unresolved", self.evaluate(rows)["failures"])

    def test_presignal_including_raw_is_rejected(self):
        for profile in ("late_half", "late_short"):
            self.assertIn(
                "unexpected_presignal_detection",
                self.evaluate(history(((3, 0), (8, 2))), profile)["failures"],
            )

    def test_last_detection_without_presignal_passes(self):
        self.assertTrue(self.evaluate(profile="late_short")["satisfied"])

    def test_forged_or_dropped_detection_rejected(self):
        for bad in ("forged", "dropped"):
            rows = history(((2, 70),))
            if bad == "forged":
                rows[1]["tests"][70]["p"] = 1.0
            else:
                rows[-1]["detected_ever"] = []
            self.assertIn("evidence_invalid", self.evaluate(rows)["failures"])

    def test_common_receipts_never_default_to_success(self):
        for key in RECEIPTS:
            receipts = dict.fromkeys(RECEIPTS, True)
            del receipts[key]
            self.assertIn("evidence_invalid", self.evaluate(receipts=receipts)["failures"])

    def test_case_scope(self):
        rows = history()
        rows[-1]["case"] = "hmac_sha256"
        self.assertIn("evidence_invalid", self.evaluate(rows)["failures"])

    def test_incomplete_and_missing_counts(self):
        rows = history()
        del rows[-1]["tests"][100]["n1"]
        self.assertFalse(self.evaluate(rows)["satisfied"])
        self.assertFalse(self.evaluate(rows[:-1])["satisfied"])

    def test_zero_and_ordinary_same_common_validity(self):
        for profile in ("zero", "ordinary"):
            self.assertTrue(self.evaluate(history(()), profile, role=True)["satisfied"])
            rows = history(())
            rows[-1]["collection_complete"] = False
            self.assertFalse(self.evaluate(rows, profile, role=True)["satisfied"])

    def test_does_not_mutate_evidence(self):
        rows = history()
        before = copy.deepcopy(rows)
        self.evaluate(rows)
        self.assertEqual(rows, before)

    def test_full_signal_detection_does_not_erase_empty_crop1_class(self):
        # Regression for the fixed F1 kernel: the other 99 crops detect, while
        # class1 begins above the pooled crop1 cutoff. This must remain failed.
        rows = history(tuple((8, i) for i in range(2, 101)))
        for row in rows:
            row["tests"][1].update(eligible=False, n0=66678, n1=0, reason="insufficient_count")
        result = self.evaluate(rows)
        self.assertFalse(result["satisfied"])
        self.assertEqual(result["first_eligible_detection_look"], 8)
        self.assertIn("count_inconclusive", result["failures"])
        self.assertNotIn("required_detection_missing", result["failures"])

    def test_other_case_characterization_not_a_presignal_failure(self):
        rows = history(((1, 7),))
        for row in rows:
            row["case"] = "ed25519_verify"
        result = evaluate(
            "nix/ed25519_verify",
            "late_half",
            rows,
            {"requirement_satisfied": True},
            dict.fromkeys(RECEIPTS, True),
        )
        self.assertTrue(result["satisfied"])
        self.assertEqual(result["presignal_detections"], [])

    def test_empty_receipts_not_accepted(self):
        self.assertIn(
            "evidence_invalid",
            evaluate("nix/ct_eq_32", "full", history(), {"requirement_satisfied": False}, {})[
                "failures"
            ],
        )


if __name__ == "__main__":
    unittest.main()
