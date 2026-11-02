# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009, PT027
"""Full102 evaluator faults with explicit logical receipts, not native trials."""

import copy
import unittest
from unittest.mock import patch

from analysis_contract import interval_test, significant
from distributed import test_moments as moment_test
from contract import CONTRACT_SHA256, LOOKS, TARGETS
from qualification import RECEIPTS, assess_kernel, digest, evaluate


def pair(n0=20000, n1=20000, shifted=False, degenerate=False):
    return [
        {"n": n, "sum": n * mean, "sum2": n * (mean * mean + (0 if degenerate else 1))}
        for n, mean in ((n0, 1000), (n1, 1002 if shifted else 1000))
    ]


def test(pair_value, idx):
    return interval_test(moment_test(pair_value, idx))


class Fixture:
    def __init__(self, detections=((2, 8),), case="nix/ct_eq_32"):
        self.case = case
        self.identity = {
            "contract_sha256": CONTRACT_SHA256,
            "source_sha256": "a" * 64,
            "analysis_sha256": "b" * 64,
        }
        self.receipts = dict.fromkeys(RECEIPTS, True)
        self.crop, self.history = [], []
        for look, batch in enumerate(LOOKS, 1):
            raw = [batch * 32763, batch * 32762]
            pairs = [pair(shifted=(look, i) in detections) for i in range(1, 101)]
            self.crop.append(
                {
                    "look": look,
                    "through_batch": batch,
                    "raw_class_counts": raw,
                    "reserved_counts": [1000, 1000],
                    "test_counts": [n - 1000 for n in raw],
                    "moments": pairs,
                    "cutoffs": [1100] * 100,
                    "tests": [test(p, i + 1) for i, p in enumerate(pairs)],
                }
            )
            tests = (
                [test(pair(*raw, shifted=(look, 0) in detections), 0)]
                + self.crop[-1]["tests"]
                + [test(pair(*raw, shifted=(look, 101) in detections), 101)]
            )
            self.history.append(
                {
                    "case": case.split("/")[1],
                    "profile": "pr",
                    "look": look,
                    "raw_class_counts": raw,
                    "collection_complete": look == 8,
                    "tests": tests,
                }
            )
        self.bind()

    def bind(self):
        seen, unresolved, crop_seen = set(), [], set()
        self.provenance = []
        for row, cr in zip(self.history, self.crop, strict=True):
            row["tests"][1:101] = cr["tests"]
            now = [t["id"] for t in row["tests"] if significant(t)]
            seen.update(now)
            unresolved.extend(
                {"look": row["look"], "statistic": t["id"]}
                for t in row["tests"]
                if t.get("reason") == "numerically_unresolved"
            )
            row.update(
                detected_now=now,
                detected_ever=sorted(seen),
                numerically_unresolved_ever=copy.deepcopy(unresolved),
            )
            crop_now = [t["id"] for t in cr["tests"] if significant(t)]
            crop_seen.update(crop_now)
            cr.update(detected_now=crop_now, detected_ever=sorted(crop_seen))
            self.provenance.append(
                {
                    "case_id": self.case,
                    "look": row["look"],
                    "through_batch": cr["through_batch"],
                    "identity": copy.deepcopy(self.identity),
                    "row_sha256": digest(row),
                    "prefix_sha256": f"{row['look']:064x}",
                    "crop_record_sha256": digest(cr),
                    "verified_native_tests": copy.deepcopy([row["tests"][0], row["tests"][101]]),
                    "native_counts": {str(i): row["raw_class_counts"].copy() for i in (0, 101)},
                }
            )

    def support(self, look, idx, *, n1=0, degenerate=False):
        p = pair(n1=n1, degenerate=degenerate)
        self.crop[look - 1]["moments"][idx - 1] = p
        self.crop[look - 1]["tests"][idx - 1] = test(p, idx)
        self.bind()

    def assess(self, profile="full"):
        return evaluate(
            self.case,
            profile,
            self.history,
            self.crop if self.case in TARGETS else None,
            self.provenance,
            self.identity,
            {
                "case_id": self.case,
                "role": "original retained separately",
                "requirement_satisfied": False,
            },
            self.receipts,
        )

    def native_scope(self):
        """Logical upstream-verifier outputs for unchanged populations."""
        self.bind()
        for row, cr, proof in zip(self.history, self.crop, self.provenance, strict=True):
            proof["verified_native_tests"] = copy.deepcopy(row["tests"])
            proof["native_counts"].update(
                {
                    str(i + 1): [m["n"] for m in pair_value]
                    for i, pair_value in enumerate(cr["moments"])
                }
            )
        return self


class QualificationTests(unittest.TestCase):
    def test_positive_other_crop_count_shortage(self):
        f = Fixture()
        f.support(8, 1)
        r = f.assess()
        self.assertTrue(r["qualification_passed"])
        self.assertFalse(r["all_final_statistics_eligible"])
        self.assertTrue(r["final_raw0_101_eligible"])
        self.assertEqual(r["support_limitations"][-1]["class_counts"], [20000, 0])

    def test_ordinary_and_zero_final_shortage(self):
        for profile in ("ordinary", "zero"):
            f = Fixture(())
            f.support(8, 1)
            self.assertIn("count_inconclusive", f.assess(profile)["failures"])

    def test_c1_other_crop_only(self):
        self.assertIn("required_detection_missing", Fixture().assess("lower_tail")["failures"])

    def test_family_raw0_or_101_only(self):
        for idx in (0, 101):
            self.assertIn("required_detection_missing", Fixture(((2, idx),)).assess()["failures"])

    def test_witness_count_10000(self):
        f = Fixture()
        f.support(2, 8, n1=10000)
        self.assertIn("required_detection_missing", f.assess()["failures"])

    def test_raw_count_199999(self):
        f = Fixture()
        f.history[-1]["raw_class_counts"][0] = 199999
        f.crop[-1]["raw_class_counts"][0] = 199999
        f.crop[-1]["test_counts"][0] = 198999
        f.bind()
        self.assertIn("count_inconclusive", f.assess()["failures"])

    def test_nonwitness_unresolved_is_sticky(self):
        f = Fixture()
        t = f.crop[3]["tests"][49]
        t.update(eligible=False, reason="numerically_unresolved")
        t["interval"]["decision"] = "numerically_unresolved"
        f.bind()
        self.assertIn("numerically_unresolved", f.assess()["failures"])

    def test_missing_receipt_or_prefix(self):
        for key in RECEIPTS:
            f = Fixture()
            del f.receipts[key]
            self.assertIn("evidence_invalid", f.assess()["failures"])
        f = Fixture()
        del f.provenance[1]["prefix_sha256"]
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_earlier_witness_may_be_ineligible_at_final(self):
        f = Fixture()
        f.support(8, 8)
        r = f.assess()
        self.assertTrue(r["qualification_passed"])
        self.assertEqual(r["first_witness"]["look"], 2)
        self.assertEqual(r["first_witness"]["prefix_binding"]["prefix_sha256"], f"{2:064x}")

    def test_p_value_without_certificate_rejected(self):
        f = Fixture()
        del f.crop[1]["tests"][7]["interval"]
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_unknown_reason_rejected(self):
        f = Fixture()
        f.support(8, 1)
        f.crop[7]["tests"][0]["reason"] = "unknown"
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_false_degenerate_rejected(self):
        f = Fixture()
        t = f.crop[7]["tests"][0]
        t.update(eligible=False, reason="degenerate_variance")
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_true_degenerate_recorded_without_p(self):
        f = Fixture()
        f.support(8, 1, n1=20000, degenerate=True)
        self.assertTrue(f.assess()["qualification_passed"])
        self.assertNotIn("p", f.crop[-1]["tests"][0])

    def test_no_witness_rejected(self):
        self.assertIn("required_detection_missing", Fixture(()).assess()["failures"])

    def test_incomplete_collection(self):
        f = Fixture()
        f.history[-1]["collection_complete"] = False
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_lost_detection_history(self):
        f = Fixture()
        f.history[-1]["detected_ever"] = []
        f.provenance[-1]["row_sha256"] = digest(f.history[-1])
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_presignal_raw_detection(self):
        f = Fixture(((1, 0), (8, 8)))
        self.assertIn("unexpected_presignal_detection", f.assess("late_half")["failures"])

    def test_raw0_101_unknown_rejected(self):
        f = Fixture()
        del f.provenance[-1]["verified_native_tests"]
        self.assertFalse(f.assess()["qualification_passed"])

    def test_raw0_101_ineligible_rejected(self):
        for idx in (0, 101):
            f = Fixture()
            f.history[-1]["tests"][idx] = {
                "id": idx,
                "eligible": False,
                "reason": "degenerate_variance",
            }
            f.bind()
            r = f.assess()
            self.assertIn("count_inconclusive", r["failures"])

    def test_zero_original_role_failure(self):
        self.assertIn("original_role_failed", Fixture().assess("zero")["failures"])

    def test_ordinary_full_coverage_passes(self):
        self.assertTrue(Fixture(()).assess("ordinary")["qualification_passed"])

    def test_unknown_case_profile_rejected(self):
        f = Fixture()
        with self.assertRaises(ValueError):
            f.assess("random")
        f.case = "nix/not_a_case"
        with self.assertRaises(ValueError):
            f.assess()

    def test_no_sparse_transfer(self):
        f = Fixture()
        f.crop[1]["tests"][7]["method"] = "exact_sparse"
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_forged_tail_bounds_rejected(self):
        f = Fixture()
        t = f.crop[1]["tests"][7]
        t["interval"]["attempts"][-1]["upper"] = [1, 2**100]
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_wrong_moment_count_rejected(self):
        f = Fixture()
        f.crop[1]["moments"][7][0]["n"] -= 1
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_moving_future_prefix_rejected(self):
        f = Fixture()
        f.provenance[1]["through_batch"] = 3
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_cross_case_evidence_rejected(self):
        f = Fixture()
        f.provenance[1]["case_id"] = "nix/hmac_sha256_key"
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_ineligible_p1_rejected(self):
        f = Fixture()
        f.support(8, 1)
        f.crop[7]["tests"][0]["p"] = 1.0
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_positive_saves_original_failed_role(self):
        r = Fixture().assess()
        self.assertTrue(r["qualification_passed"])
        self.assertFalse(r["original_role_result"]["requirement_satisfied"])

    def test_actual_c1_witness(self):
        self.assertTrue(Fixture(((2, 1),)).assess("lower_tail")["qualification_passed"])

    def test_expired_verification_deadline(self):
        f = Fixture()
        r = evaluate(
            f.case, "full", f.history, f.crop, f.provenance, f.identity, {}, f.receipts, deadline=0
        )
        self.assertFalse(r["qualification_passed"])

    def test_nontarget_never_gets_positive_waiver(self):
        f = Fixture((), case="legacy/hmac_key_reject").native_scope()
        self.assertTrue(f.assess()["qualification_passed"])
        f.support(8, 1)
        f.native_scope()
        self.assertIn("count_inconclusive", f.assess()["failures"])

    def test_ct64_positive_and_zero_have_separate_requirements(self):
        f = Fixture(((2, 1),), case="nix/ct_eq_64")
        f.support(8, 1)
        f.bind()
        self.assertTrue(f.assess("full")["qualification_passed"])
        self.assertFalse(f.assess("zero")["qualification_passed"])
        z = Fixture((), case="nix/ct_eq_64")
        self.assertTrue(z.assess("zero")["qualification_passed"])
        z.support(8, 1)
        z.bind()
        self.assertIn("count_inconclusive", z.assess("zero")["failures"])

    def test_new_targets_need_signal_and_zero_still_needs_all_crops(self):
        for case in ("nix/sha256", "nix/ct_eq_128"):
            positive = Fixture(((2, 1),), case=case)
            positive.support(8, 1)
            self.assertTrue(positive.assess("full")["qualification_passed"])
            self.assertFalse(positive.assess("zero")["qualification_passed"])
            zero = Fixture((), case=case)
            self.assertTrue(zero.assess("zero")["qualification_passed"])
            self.assertIn("required_detection_missing", zero.assess("full")["failures"])
            zero.support(8, 1)
            self.assertIn("count_inconclusive", zero.assess("zero")["failures"])

    def test_original_controls_keep_specified_statistic(self):
        for name, required in (("control_mean_shift", 0), ("control_variance_shift", 101)):
            f = Fixture(((2, required),), case="nix/" + name).native_scope()
            self.assertTrue(f.assess()["qualification_passed"])
            f.support(8, 1)
            f.native_scope()
            corrected = f.assess()
            self.assertTrue(corrected["qualification_passed"])
            self.assertFalse(corrected["all_final_statistics_eligible"])
            self.assertEqual(
                corrected["native_support_limitations"][-1]["class_counts"], [20000, 0]
            )
            wrong = Fixture(((2, 8),), case="nix/" + name).native_scope()
            self.assertIn("original_role_failed", wrong.assess()["failures"])

    def test_characterization_retains_detection_and_coverage(self):
        f = Fixture(case="nix/ed25519_verify").native_scope()
        f.support(8, 1)
        f.native_scope()
        r = f.assess()
        self.assertTrue(r["qualification_passed"])
        self.assertFalse(r["all_final_statistics_eligible"])
        self.assertEqual(r["statistical_outcome"], "detected")
        self.assertIsNone(r["sensitivity_requirement_satisfied"])

    def test_kernel_prerequisites_remain_unknown(self):
        f = Fixture()
        r = assess_kernel({"case_id": f.case, "profile": "full", "looks": f.crop})
        self.assertTrue(r["crop_expectation_met"])
        for key in (
            "qualification_passed",
            "all_final_statistics_eligible",
            "final_raw0_101_eligible",
        ):
            self.assertIsNone(r[key])

    def test_changed_alpha_rejected(self):
        f = Fixture()
        f.crop[1]["tests"][7]["alpha"] *= 2
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_mismatched_crop_binding_rejected(self):
        f = Fixture()
        f.provenance[1]["crop_record_sha256"] = "0" * 64
        self.assertIn("evidence_invalid", f.assess()["failures"])

    def test_deadline_after_verification_is_not_success(self):
        f = Fixture()
        # Model a verifier consuming the remaining time before the final check.
        from qualification import inspect_crops  # noqa: PLC0415 -- retain initialization order of the measured analysis

        verified = inspect_crops(f.case, "full", f.crop)
        with (
            patch("qualification.inspect_crops", return_value=verified),
            patch("qualification.tail_decision", return_value="nondetected"),
            patch("qualification.time.monotonic", side_effect=[0, 2]),
        ):
            r = evaluate(
                f.case,
                "full",
                f.history,
                f.crop,
                f.provenance,
                f.identity,
                {},
                f.receipts,
                deadline=1,
            )
        self.assertIn("evidence_invalid", r["failures"])

    def test_nonboolean_native_eligibility_rejected(self):
        f = Fixture()
        f.history[-1]["tests"][0]["eligible"] = 1
        f.bind()
        self.assertIn("evidence_invalid", f.assess()["failures"])


if __name__ == "__main__":
    unittest.main()
