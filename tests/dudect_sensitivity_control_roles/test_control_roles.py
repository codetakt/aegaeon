# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009
"""Role precedence regressions; logical evidence, not physical timing trials."""

import copy
import unittest
from test_qualification import Fixture, pair
from qualification import digest

CONTROLS = [
    (suite + "/" + name, idx)
    for suite in ("legacy", "nix")
    for name, idx in (("control_mean_shift", 0), ("control_variance_shift", 101))
]


def fixture(case, idx):
    f = Fixture(((2, idx),), case=case)
    f.support(8, 1)
    return f.native_scope()


class OriginalControlRoles(unittest.TestCase):
    def test_four_original_controls_keep_witness_and_report_missing_crop(self):
        for case, idx in CONTROLS:
            f = fixture(case, idx)
            r = f.assess("ordinary")
            self.assertTrue(r["qualification_passed"], case)
            self.assertFalse(r["all_final_statistics_eligible"])
            self.assertTrue(r["raw_floor_met"])
            self.assertEqual(r["native_support_limitations"][-1]["class_counts"], [20000, 0])

    def test_all_crops_ineligible_does_not_erase_designated_witness(self):
        for case, idx in CONTROLS:
            f = fixture(case, idx)
            for cr in f.crop:
                cr["tests"] = [
                    {"id": i, "eligible": False, "reason": "insufficient_count"}
                    for i in range(1, 101)
                ]
                cr["moments"] = [pair(n0=0, n1=0) for _ in range(100)]
            f.native_scope()
            self.assertTrue(f.assess("ordinary")["qualification_passed"])

    def test_no_designated_witness_still_fails(self):
        for case, idx in CONTROLS:  # noqa: B007 -- iteration cardinality is part of the fixture
            f = Fixture((), case=case).native_scope()
            self.assertIn("original_role_failed", f.assess("ordinary")["failures"])

    def test_other_raw_statistic_does_not_substitute(self):
        for case, idx in CONTROLS:
            f = Fixture(((2, 101 - idx),), case=case).native_scope()
            self.assertIn("original_role_failed", f.assess("ordinary")["failures"])

    def test_earlier_designated_witness_survives_final_ineligibility(self):
        for case, idx in CONTROLS:
            f = fixture(case, idx)
            f.history[-1]["tests"][idx] = {
                "id": idx,
                "eligible": False,
                "reason": "degenerate_variance",
            }
            f.native_scope()
            r = f.assess("ordinary")
            self.assertTrue(r["qualification_passed"])
            self.assertFalse(r["final_raw0_101_eligible"])

    def test_raw_floor_preserved(self):
        for case, idx in CONTROLS:
            f = fixture(case, idx)
            f.history[-1]["raw_class_counts"][0] = 199999
            f.native_scope()
            self.assertIn("count_inconclusive", f.assess("ordinary")["failures"])

    def test_witness_below_count_floor_rejected(self):
        for case, idx in CONTROLS:
            f = fixture(case, idx)
            f.provenance[1]["native_counts"][str(idx)] = [10000, 20000]
            self.assertIn("evidence_invalid", f.assess("ordinary")["failures"])

    def test_missing_certificate_rejected(self):
        for case, idx in CONTROLS:
            f = fixture(case, idx)
            del f.history[1]["tests"][idx]["interval"]
            f.provenance[1]["row_sha256"] = digest(f.history[1])
            f.provenance[1]["verified_native_tests"] = copy.deepcopy(f.history[1]["tests"])
            self.assertIn("evidence_invalid", f.assess("ordinary")["failures"])

    def test_nonwitness_numerical_failure_not_waived(self):
        for case, idx in CONTROLS:
            f = fixture(case, idx)
            f.crop[2]["tests"][40] = {
                "id": 41,
                "eligible": False,
                "reason": "numerically_unresolved",
            }
            f.native_scope()
            self.assertIn("numerically_unresolved", f.assess("ordinary")["failures"])

    def test_missing_collection_not_waived(self):
        for case, idx in CONTROLS:
            f = fixture(case, idx)
            f.history[-1]["collection_complete"] = False
            f.native_scope()
            self.assertIn("evidence_invalid", f.assess("ordinary")["failures"])

    def test_missing_receipt_not_waived(self):
        for case, idx in CONTROLS:
            for key in ("binding", "frames", "inputs", "signal", "resources", "process"):
                f = fixture(case, idx)
                f.receipts[key] = False
                self.assertIn("evidence_invalid", f.assess("ordinary")["failures"])

    def test_wrong_native_identity_not_waived(self):
        f = fixture(*CONTROLS[0])
        f.provenance[0]["case_id"] = "nix/ct_eq_64"
        self.assertIn("evidence_invalid", f.assess("ordinary")["failures"])

    def test_lost_detection_not_waived(self):
        f = fixture(*CONTROLS[0])
        f.history[-1]["detected_ever"] = []
        self.assertIn("evidence_invalid", f.assess("ordinary")["failures"])

    def test_nonpositive_roles_keep_final_coverage(self):
        for case in ("nix/control_independent", "legacy/hmac_key_reject"):
            f = Fixture((), case=case)
            f.support(8, 1)
            f.native_scope()
            self.assertIn("count_inconclusive", f.assess("ordinary")["failures"])

    def test_invalid_ineligibility_is_not_success(self):
        f = fixture(*CONTROLS[0])
        f.crop[-1]["tests"][0]["reason"] = "unexplained"
        f.native_scope()
        self.assertIn("evidence_invalid", f.assess("ordinary")["failures"])

    def test_same_frozen_history_does_not_change_source(self):
        f = fixture(*CONTROLS[0])
        before = copy.deepcopy((f.history, f.provenance))
        f.assess("ordinary")
        self.assertEqual(before, (f.history, f.provenance))


if __name__ == "__main__":
    unittest.main()
