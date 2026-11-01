# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009
import copy  # noqa: F401 -- retain measured import initialization
import unittest
from test_qualification import Fixture, pair
from qualification import digest
from contract import ROLES
from dudect_contract import CHARACTERIZATION_ROLES

CASES = [c for c, r in ROLES.items() if r in CHARACTERIZATION_ROLES]


class CharacterizationTests(unittest.TestCase):
    def fixture(self, case):
        f = Fixture((), case=case)
        f.support(8, 1)
        return f.native_scope()

    def test_all_five_bound_roles(self):
        self.assertEqual(len(CASES), 5)
        for c in CASES:
            r = self.fixture(c).assess("ordinary")
            self.assertTrue(r["role_requirement_satisfied"])
            self.assertIsNone(r["sensitivity_requirement_satisfied"])
            self.assertFalse(r["all_final_statistics_eligible"])
            self.assertEqual(r["statistical_outcome"], "not_evaluable")
            self.assertNotIn("sensitivity_qualified", r)

    def test_all_crops_and_raw_degenerate_can_be_reported(self):
        for c in CASES:
            f = self.fixture(c)
            for row in f.crop:
                row["tests"] = [
                    {"id": i, "eligible": False, "reason": "insufficient_count"}
                    for i in range(1, 101)
                ]
                row["moments"] = [pair(n0=0, n1=0) for _ in range(100)]
            for row in f.history:
                for i in (0, 101):
                    row["tests"][i] = {"id": i, "eligible": False, "reason": "degenerate_variance"}
            f.native_scope()
            r = f.assess("ordinary")
            self.assertTrue(r["qualification_passed"])
            self.assertFalse(r["final_raw0_101_eligible"])
            self.assertEqual(r["statistical_outcome"], "not_evaluable")

    def test_common_faults_never_waived(self):  # noqa: C901, PLR0912 -- ordered evidence checks retain each rejection boundary
        for c in CASES:
            for fault in (
                "raw",
                "collection",
                "receipt",
                "numeric",
                "unknown",
                "fake_count",
                "history",
                "deadline",
            ):
                f = self.fixture(c)
                if fault == "raw":
                    f.history[-1]["raw_class_counts"][0] = 199999
                if fault == "collection":
                    f.history[-1]["collection_complete"] = False
                if fault == "receipt":
                    f.receipts["frames"] = False
                if fault == "numeric":
                    f.crop[2]["tests"][40] = {
                        "id": 41,
                        "eligible": False,
                        "reason": "numerically_unresolved",
                    }
                if fault == "unknown":
                    f.crop[-1]["tests"][0]["reason"] = "unknown"
                if fault == "fake_count":
                    f.crop[-1]["moments"][0] = pair()
                f.native_scope()
                if fault == "history":
                    f.history[-1]["detected_ever"] = [42]
                    f.provenance[-1]["row_sha256"] = digest(f.history[-1])
                if fault == "deadline":
                    from qualification import evaluate  # noqa: PLC0415 -- retain initialization order of the measured analysis

                    r = evaluate(
                        c,
                        "ordinary",
                        f.history,
                        None,
                        f.provenance,
                        f.identity,
                        {},
                        f.receipts,
                        deadline=0,
                    )
                else:
                    r = f.assess("ordinary")
                self.assertFalse(r["qualification_passed"], (c, fault))

    def test_role_string_cannot_grant_waiver(self):
        f = Fixture((), case="legacy/hmac_key_reject")
        f.support(8, 1)
        f.native_scope()
        r = f.assess("ordinary")
        self.assertFalse(r["qualification_passed"])
        self.assertEqual(r["role"], "protected_input_observation")

    def test_legacy_compare_is_a_separate_calibrated_negative(self):
        f = Fixture((), case="legacy/compare")
        self.assertTrue(f.assess("ordinary")["qualification_passed"])
        f.support(8, 1)
        self.assertFalse(f.assess("ordinary")["qualification_passed"])
        f = Fixture(((2, 1),), case="legacy/compare")
        self.assertTrue(f.assess("full")["sensitivity_requirement_satisfied"])
        self.assertFalse(f.assess("zero")["role_requirement_satisfied"])


if __name__ == "__main__":
    unittest.main()
