# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009, PT027
import copy
from collections import Counter
import struct
import os
from pathlib import Path
import subprocess
import sys
import unittest

from analysis_contract import History, assess, interval_test  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
from candidate import ScopedPartition, CONTRACT, CASES
from deadline import review
from distributed import Partition, selectors, cutoffs, cropped_moments, test_moments as moments_test  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
from dudect_candidate import canonical, digest


def payload(case, size=64, shift=0, label_flip=0):
    ticks = [0]
    for i in range(size - 1):
        ticks.append(ticks[-1] + 100 + i % 3 + shift)
    width = 0 if case in ("ct_eq_32", "ct_eq_64", "ct_eq_128", "compare") else 32
    return (
        struct.pack(f"<{size}q", *ticks)
        + bytes((i + label_flip) % 2 for i in range(size))
        + bytes(size * width)
    )


def row_proof(partition, look=1):
    counts = [
        sum(h.values()) + partition.reserved_by_class[g] for g, h in enumerate(partition.testing)
    ]
    row = {
        "case": partition.name,
        "binding": {"case_id": partition.case_id},
        "profile": "pr",
        "look": look,
        "batches": partition.batch,
        "statistics": [counts],
        "rejected": partition.rejected,
    }
    proof = {
        "row_sha256": digest(canonical(row)),
        "case": partition.name,
        "look": look,
        "through_batch": partition.batch,
        "prefix_start": 0,
        "prefix_end": 100,
        "case_start": 0,
        "prefix_sha256": "fixture",
    }
    return row, proof


def history(detect=8, insufficient=7):
    rows, seen = [], []
    for look in range(1, 9):
        tests = [
            {"id": i, "eligible": True, "n0": 20000, "n1": 20000, "p": 1.0} for i in range(102)
        ]
        if look <= insufficient:
            tests[1].update(eligible=False, n1=9000, reason="insufficient_count")
        now = [1] if look == detect else []
        if now:
            tests[1]["p"] = 0.0
        seen += now
        rows.append(
            {
                "case": "hmac_sha256",
                "profile": "pr",
                "look": look,
                "collection_complete": look == 8,
                "raw_class_counts": [500000, 500000],
                "numerically_unresolved_ever": [],
                "tests": tests,
                "detected_now": now,
                "detected_ever": sorted(set(seen)),
                "candidate_statistical_outcome": "leakage_detected" if seen else "collecting",
            }
        )
    return rows


class PartitionTests(unittest.TestCase):
    def test_fixed_scope(self):
        self.assertEqual(
            CASES,
            {
                "nix/hmac_sha256_key",
                "nix/ct_eq_64",
                "nix/sha256",
                "nix/ct_eq_32",
                "nix/hmac_sha256",
                "nix/ct_eq_128",
                "legacy/compare",
            },
        )
        self.assertEqual(CONTRACT["compilers"], ["gcc", "clang"])
        for case in ("nix/ed25519_verify", "legacy/hmac_key_reject"):
            with self.assertRaises(ValueError):
                ScopedPartition("packet", "unit", case)

    def test_six_cases_have_same_fixed_math_but_separate_identity(self):
        states = [
            ScopedPartition("p", "u", "nix/" + case)
            for case in (
                "ct_eq_32",
                "ct_eq_64",
                "ct_eq_128",
                "sha256",
                "hmac_sha256",
                "hmac_sha256_key",
            )
        ]
        for state in states:
            for batch in (0, 1):
                state.push(payload(state.name), batch, 64)
        rows = [state.evaluate(*row_proof(state)) for state in states]
        for row in rows[1:]:
            for key in ("cutoffs", "moments", "tests", "slot_assignment_sha256"):
                self.assertEqual(rows[0][key], row[key])
        self.assertEqual(len({r["analysis_binding"]["case_id"] for r in rows}), 6)
        for state in states[1:]:
            with self.assertRaises(ValueError):
                state.evaluate(*row_proof(states[0]))

    def test_same_split_and_moments_as_hmac_kernel(self):
        old, new = Partition("p", "u"), ScopedPartition("p", "u", "nix/hmac_sha256")
        for b in (0, 1):
            data = payload("hmac_sha256")
            old.push(data, b, 64)
            new.push(data, b, 64)
        self.assertEqual(old.calibration, new.calibration)
        self.assertEqual(old.testing, new.testing)
        row, proof = row_proof(new)
        actual = new.evaluate(row, proof)
        prior = old.evaluate(row, proof)
        for key in ("cutoffs", "moments", "tests", "slot_assignment_sha256", "test_counts"):
            self.assertEqual(actual[key], prior[key])

    def test_each_case_has_separate_state(self):
        a = ScopedPartition("p", "u", "nix/ct_eq_32")
        b = ScopedPartition("p", "u", "nix/hmac_sha256_key")
        a.push(payload("ct_eq_32"), 0, 64)
        a.push(payload("ct_eq_32"), 1, 64)
        self.assertEqual(b.calibration, Counter())
        self.assertEqual(b.batch, -1)
        row, proof = row_proof(a)
        row["binding"]["case_id"] = b.case_id
        with self.assertRaises(ValueError):
            a.evaluate(row, proof)

    def test_pilot_excluded(self):
        a = ScopedPartition("p", "u", "nix/ct_eq_32")
        a.push(payload("ct_eq_32", shift=10000), 0, 64)
        self.assertEqual(sum(a.calibration.values()), 0)
        a.push(payload("ct_eq_32"), 1, 64)
        self.assertLess(max(a.calibration), 200)

    def test_label_and_time_do_not_change_selection(self):
        objects = []
        for flip, shift in ((0, 0), (1, 1000)):
            a = ScopedPartition("p", "u", "nix/ct_eq_32")
            for b in (0, 1):
                a.push(payload("ct_eq_32", shift=shift, label_flip=flip), b, 64)
            objects.append(a)
        self.assertEqual(objects[0].slot_digest.digest(), objects[1].slot_digest.digest())

    def test_reserved_test_disjoint_and_complete(self):
        a = ScopedPartition("p", "u", "nix/ct_eq_32")
        for b in (0, 1):
            a.push(payload("ct_eq_32"), b, 64)
        self.assertEqual(
            sum(a.calibration.values()) + sum(map(lambda h: sum(h.values()), a.testing)),  # noqa: C417 -- retain the frozen fixture transformation
            53,
        )
        self.assertEqual(sum(a.reserved_by_class), sum(a.calibration.values()))

    def test_bad_width_missing_reorder_and_future(self):
        for batch, width in ((1, 0), (0, 32)):
            a = ScopedPartition("p", "u", "nix/ct_eq_32")
            data = payload("hmac_sha256" if width else "ct_eq_32")
            with self.assertRaises(ValueError):
                a.push(data, batch, 64)
        a = ScopedPartition("p", "u", "nix/ct_eq_32")
        a.push(payload("ct_eq_32"), 0, 64)
        for batch in (0, 2, 17):
            with self.assertRaises(ValueError):
                a.push(payload("ct_eq_32"), batch, 64)

    def test_future_prefix_not_used(self):
        a = ScopedPartition("p", "u", "nix/ct_eq_32")
        for b in (0, 1, 2):
            a.push(payload("ct_eq_32"), b, 64)
        row, proof = row_proof(a, 1)
        with self.assertRaises(ValueError):
            a.evaluate(row, proof)

    def test_periodic_rejected(self):
        a = ScopedPartition("p", "u", "nix/ct_eq_32")
        for b in (0, 1):
            a.push(payload("ct_eq_32"), b, 64)
        row, proof = row_proof(a)
        row["profile"] = "periodic"
        with self.assertRaises(ValueError):
            a.evaluate(row, proof)

    def test_wrong_row_digest_and_reserved_mix_rejected(self):
        a = ScopedPartition("p", "u", "nix/ct_eq_32")
        for b in (0, 1):
            a.push(payload("ct_eq_32"), b, 64)
        row, proof = row_proof(a)
        proof["row_sha256"] = "bad"
        with self.assertRaises(ValueError):
            a.evaluate(row, proof)
        row, proof = row_proof(a)
        a.testing[0][100] += 1
        with self.assertRaises(ValueError):
            a.evaluate(row, proof)

    def test_inclusive_ties(self):
        limits = cutoffs(Counter({100: 10000, 101: 1}))
        self.assertEqual(limits[0], 100)
        self.assertEqual(cropped_moments(Counter({100: 9999, 101: 5}), [100])[0]["n"], 9999)

    def test_one_class_floor_and_degenerate_not_supplemented(self):
        for n in (9999, 10000):
            pair = [{"n": 20000, "sum": 30000, "sum2": 50000}, {"n": n, "sum": n, "sum2": n}]
            self.assertEqual(interval_test(moments_test(pair, 1))["reason"], "insufficient_count")
        pair = [{"n": 10001, "sum": 10001, "sum2": 10001}] * 2
        self.assertEqual(interval_test(moments_test(pair, 1))["reason"], "degenerate_variance")

    def test_threshold_moves_recompute_counts(self):
        h = Counter({100: 9000, 101: 2000, 102: 10000})
        self.assertEqual([cropped_moments(h, [x])[0]["n"] for x in (101, 100)], [11000, 9000])

    def test_history_retains_detection_after_recalibration(self):
        hist = History()
        base = {
            "case": "ct_eq_32",
            "profile": "pr",
            "raw_count": 1000000,
            "raw_class_counts": [500000, 500000],
        }
        for look in range(1, 9):
            tests = [{"id": i, "eligible": True, "p": 1.0} for i in range(102)]
            if look == 2:
                tests[1]["p"] = 0.0
            if look == 3:
                tests[1] = {"id": 1, "eligible": False, "reason": "insufficient_count"}
            result = hist.append({"look": look, "profile": "pr"}, {**base, "look": look}, tests)
        self.assertEqual(result["detected_ever"], [1])


class DeadlineTests(unittest.TestCase):
    role = {"requirement_satisfied": False, "failure": "leakage_detected"}  # noqa: RUF012 -- shared constant fixture is copied by each test

    def test_final_detection_does_not_rewrite_old_early_failure(self):
        rows = history()
        before = copy.deepcopy(rows)
        r = review(rows, "early", self.role)
        self.assertFalse(r["historical_rule_on_supplied_history"]["passed"])
        self.assertTrue(r["fixed_budget_candidate"]["passed"])
        self.assertEqual(r["first_crop1_count_sufficient_look"], 8)
        self.assertEqual(r["first_crop1_detection_look"], 8)
        self.assertFalse(r["detected_within_early_window"])
        self.assertEqual(rows, before)

    def test_early_detection_preserved_with_late_nondetection(self):
        r = review(history(6, 5), "early", self.role)
        self.assertTrue(r["fixed_budget_candidate"]["passed"])
        self.assertEqual(r["first_crop1_detection_look"], 6)

    def test_other_statistic_cannot_substitute(self):
        rows = history(None, 0)
        rows[7]["detected_now"] = [0]
        rows[7]["detected_ever"] = [0]
        rows[7]["tests"][0]["p"] = 0.0
        self.assertFalse(review(rows, "early", self.role)["fixed_budget_candidate"]["passed"])

    def test_final_floor_still_required(self):
        rows = history(6, 5)
        rows[7]["tests"][1].update(eligible=False, n1=10000)
        self.assertFalse(review(rows, "early", self.role)["fixed_budget_candidate"]["passed"])

    def test_invalid_detection_is_rejected(self):
        rows = history()
        rows[7]["tests"][1]["eligible"] = False
        with self.assertRaises(ValueError):
            review(rows, "early", self.role)

    def test_late_presignal_detection_kept_failure(self):
        self.assertFalse(
            review(history(6, 5), "late", self.role)["fixed_budget_candidate"]["passed"]
        )

    def test_missing_look_and_raw_floor_cannot_pass(self):
        rows = history()
        rows[-1]["raw_class_counts"] = [199999, 500000]
        self.assertFalse(review(rows, "early", self.role)["fixed_budget_candidate"]["passed"])
        self.assertFalse(
            review(history()[1:], "early", self.role)["fixed_budget_candidate"]["passed"]
        )

    def test_unresolved_sticky_failure(self):
        rows = history()
        rows[-1]["numerically_unresolved_ever"] = [{"look": 4, "statistic": 50}]
        self.assertFalse(review(rows, "early", self.role)["fixed_budget_candidate"]["passed"])

    def test_any_prior_detection_must_survive(self):
        rows = history(6, 5)
        rows[5]["detected_now"].append(2)
        rows[5]["detected_ever"].append(2)
        rows[5]["tests"][2]["p"] = 0.0
        self.assertFalse(review(rows, "early", self.role)["fixed_budget_candidate"]["passed"])

    def test_zero_still_requires_original_role(self):
        self.assertFalse(
            review(history(None, 0), "zero", self.role)["fixed_budget_candidate"]["passed"]
        )

    def test_counts_are_read_from_moments_when_welch_omits_them(self):
        rows = history()
        counts = [[20000, 9000]] * 7 + [[20000, 20000]]
        for row in rows[:7]:
            row["tests"][1].pop("n0")
            row["tests"][1].pop("n1")
        self.assertFalse(review(rows, "early", self.role)["counts_complete"])
        value = review(rows, "early", self.role, counts)
        self.assertTrue(value["counts_complete"])
        self.assertEqual(value["first_crop1_count_sufficient_look"], 8)

    def test_forged_detection_flag_rejected(self):
        rows = history()
        rows[7]["tests"][1]["p"] = 1.0
        with self.assertRaises(ValueError):
            review(rows, "early", self.role)

    def test_standalone_import_bootstraps_native_helpers(self):
        result = subprocess.run(  # noqa: PLW1510 -- return code is inspected and retained after capture
            [sys.executable, "-B", "-c", "import deadline"],
            cwd=Path(__file__).parent,
            env=os.environ,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
