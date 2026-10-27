# ruff: noqa: PT009, PT027, S603 - exact controls and native compiler test
"""Prospective exact single-outlier inference and original-frame certificates."""

from __future__ import annotations

import itertools
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))

from dudect_candidate import ALPHA, NUMERICAL_SHA256, CandidateAdmission, significant
from dudect_certificates import Certificates
from dudect_contract import ObservationError, assess_case
from dudect_results import BATCH_SIZE, CANDIDATE_PROFILES
from dudect_summary import summarize_case
from dudect_support import single_outlier, single_outlier_tail, validate_support
from dudect_timing import TIMING_ENV, validate_timing
from test_dudect_candidate import ROOT, binding, observation, support
from test_dudect_timing import SCHEDULE_PROBE


def outlier_row(  # noqa: PLR0913 - independent boundary dimensions
    group=0, *, low=60, high=62, exceptional_count=1, exceptional_high=False, center=100
):
    row = observation(constant=True)
    row["pilot"] = {"count": 65525, "center": center, "cutoffs": [max(200, high)] * 100}
    common, rare = (low, high) if exceptional_high else (high, low)
    for index in range(102):
        transform = float if index < 101 else lambda x: (float(x) - center) * (float(x) - center)
        usual, unusual = transform(common), transform(rare)
        delta = unusual - usual
        for label, n in enumerate(row["statistics"][index][:2]):
            row["statistics"][index][2 + label] = usual
            row["statistics"][index][4 + label] = 0
            row["support"][index][label] = support(n, common, common, usual, usual)
        n = row["statistics"][index][group]
        row["statistics"][index][2 + group] = usual + delta * exceptional_count / n
        row["statistics"][index][4 + group] = (
            delta * delta * exceptional_count * (n - exceptional_count) / n
        )
        item = support(n, low, high, min(usual, unusual), max(usual, unusual))
        item.update(
            tick_min_count=n - exceptional_count if exceptional_high else exceptional_count,
            tick_max_count=exceptional_count if exceptional_high else n - exceptional_count,
        )
        row["support"][index][group] = item
    return row


class SingleOutlierTests(unittest.TestCase):
    def test_exact_tail_matches_every_small_label_permutation(self):
        for n0, n1 in itertools.product(range(1, 6), repeat=2):
            for group in (0, 1):
                samples = [3] + [7] * (n0 + n1 - 1)
                observed = Fraction(4, (n0, n1)[group])
                differences = [
                    abs(
                        Fraction(sum(samples[i] for i in left), n0)
                        - Fraction(sum(samples[i] for i in range(n0 + n1) if i not in left), n1)
                    )
                    for left in itertools.combinations(range(n0 + n1), n0)
                ]
                exact = Fraction(sum(d >= observed for d in differences), len(differences))
                self.assertEqual(Fraction(*single_outlier_tail([n0, n1], group)), exact)

    def test_both_exceptional_classes_and_transforms_use_exact_tail(self):
        for group, high in itertools.product((0, 1), (False, True)):
            row = outlier_row(group, exceptional_high=high)
            result = CandidateAdmission("compare", "pr", binding=binding()).admit(row)
            wanted = single_outlier_tail(row["statistics"][0][:2], group)
            for test in result["tests"]:
                self.assertEqual(test["p_exact"], list(wanted))
                self.assertEqual(
                    test["method"], "exact_absolute_mean_permutation_single_native_outlier"
                )

    def test_two_exceptions_and_interior_values_remain_unsupported(self):
        for count in (2, 3, 100):
            row = outlier_row(exceptional_count=count)
            result = CandidateAdmission("compare", "pr", binding=binding()).admit(row)
            self.assertTrue(all(not test["eligible"] for test in result["tests"]))
        row = outlier_row()
        row["support"][0][0]["tick_max_count"] -= 1
        self.assertIsNone(single_outlier(row, 0))

    def test_sparse_alias_and_squared_collision_exclusions(self):
        row = outlier_row()
        row["support"][0][0]["count"] = 10000
        self.assertIsNone(single_outlier(row, 0))
        for row in (outlier_row(low=2**53, high=2**53 + 1), outlier_row(center=61)):
            result = CandidateAdmission("compare", "pr", binding=binding()).admit(row)
            self.assertFalse(result["tests"][101]["eligible"])
            self.assertEqual(result["tests"][0]["eligible"], row["pilot"]["center"] == 61)

    def test_forged_counts_and_regression_fail_before_inference(self):
        for key, value in (
            ("tick_min_count", 0),
            ("tick_max_count", 999999),
            ("tick_min_count", True),
        ):
            row = outlier_row()
            row["support"][0][0][key] = value
            with self.assertRaises(ValueError):
                validate_support(row)
        row = observation(constant=True)
        row["support"][0][0].pop("tick_min_count")
        with self.assertRaises(ValueError):
            validate_support(row)
        previous, current = observation(), observation(look=2)
        previous["support"][0][0]["tick_min_count"] = 2
        with self.assertRaisesRegex(ValueError, "multiplicity regressed"):
            validate_support(current, previous)

    def test_prior_detection_and_old_identity_are_not_erased(self):
        admission = CandidateAdmission("compare", "pr", binding=binding())
        admission.admit(observation(effect=True))
        # A new complete history with a first-look effect remains absorbing;
        # exact inference is checked separately above, with native histories below.
        for look in range(2, 9):
            result = admission.admit(observation(look=look))
        self.assertEqual(result["candidate_statistical_outcome"], "leakage_detected")
        old = observation()
        old["schema_version"] = 4
        with self.assertRaisesRegex(ValueError, "Version 5"):
            CandidateAdmission("compare", "pr", binding=binding()).admit(old)
        old = observation()
        old["binding"]["numerical_sha256"] = (
            "ff0c53a9b2fd02566e98390011dc131bb834ec66033892def3217658492c1340"
        )
        with self.assertRaises(ValueError):
            CandidateAdmission("compare", "pr", binding=old["binding"]).admit(old)

    def test_exact_tail_keeps_an_earlier_detection_absorbing(self):
        admission = CandidateAdmission("compare", "pr", binding=binding())
        for look in (1, 2):
            row = observation(look=look, effect=look == 1)
            rare = outlier_row()
            for group, n in enumerate(row["statistics"][0][:2]):
                row["support"][0][group] = support(n, 50, 110, 50, 110)
                row["statistics"][0][4 + group] = n * 100
                row["support"][101][group] = support(n, 50, 110, 0, 2500)
                row["statistics"][101][2 + group] = 100
                row["statistics"][101][4 + group] = n * 1000
            # One qualifying crop; other statistics retain positive-variance Welch.
            row["support"][1] = rare["support"][1]
            row["statistics"][1] = rare["statistics"][1]
            result = admission.admit(row)
            self.assertIn("p_exact", result["tests"][1])
            self.assertEqual(result["candidate_statistical_outcome"], "leakage_detected")

    def test_rational_threshold_does_not_round_a_smaller_tail_to_alpha(self):
        numerator, denominator = ALPHA.as_integer_ratio()
        for offset, expected in ((-1, True), (0, False), (1, False)):
            tail = [numerator * 1024 + offset, denominator * 1024]
            self.assertEqual(tail[0] / tail[1], ALPHA)
            self.assertEqual(significant({"eligible": True, "p": ALPHA, "p_exact": tail}), expected)

    def test_exact_tail_consumers_preserve_the_shared_threshold_boundary(self):
        # These synthetic ratios test the consumer interface. They cannot arise
        # from the current bounded single-outlier family (proved below).
        rows = [observation("control_mean_shift", look=i) for i in range(1, 9)]
        bound = rows[0]["binding"]
        admission = CandidateAdmission("control_mean_shift", "pr", binding=bound)
        baseline = [admission.admit(row) for row in rows]
        numerator, denominator = ALPHA.as_integer_ratio()
        for offset in (-1, 0, 1):
            history = json.loads(json.dumps(baseline))
            test = history[0]["tests"][0]
            test.update(p=ALPHA, p_exact=[numerator * 1024 + offset, denominator * 1024])
            args = (bound["case_id"], "measurement_positive_control", history, "pr")
            if offset < 0:
                self.assertTrue(assess_case(*args)["requirement_satisfied"])
            else:
                with self.assertRaises(ObservationError):
                    assess_case(*args)
            with patch.object(CandidateAdmission, "admit", side_effect=history):
                diagnostic = summarize_case(rows, bound, "measurement_positive_control")
            self.assertEqual(diagnostic["requirement_satisfied"], offset < 0)
            self.assertEqual(
                diagnostic["looks"][0]["detected_statistics"], [test] if offset < 0 else []
            )

    def test_admissible_single_outlier_cannot_reach_the_alpha_boundary(self):
        largest_pooled_count = (BATCH_SIZE - 11) * CANDIDATE_PROFILES["periodic"][0][-1]
        smallest_tail = Fraction(10001, largest_pooled_count)
        self.assertGreater(smallest_tail, Fraction(ALPHA))

    def test_forged_single_outlier_is_rejected_by_original_frames(self):
        row = outlier_row()
        certificate = Certificates([row])
        ticks = list(itertools.accumulate([0] + [62] * (BATCH_SIZE - 1)))
        payload = struct.pack(f"<{BATCH_SIZE}q", *ticks) + bytes(i % 2 for i in range(BATCH_SIZE))
        with self.assertRaisesRegex(ValueError, "differs from original"):
            certificate.push(payload, 1, BATCH_SIZE)
        with self.assertRaisesRegex(ValueError, "Missing single-outlier"):
            Certificates([row]).finish()

    def test_native_endpoint_counts_and_full_schedules_replay(self):
        # Real producer, complete fixed schedules and the original trace consumer.
        source_text = SCHEDULE_PROBE.replace(
            "ctx->ticks[i] = (int64_t)i * 62;\n        ctx->exec_times[i] = 62;",
            "ctx->ticks[i] = i ? ctx->ticks[i-1] + ctx->exec_times[i-1] : 0;\n"
            "        ctx->exec_times[i] = ctx->batches == 11 && "
            "i == 16738 + EXCEPTION_CLASS ? 60 : 62;",
        )
        self.assertNotEqual(source_text, SCHEDULE_PROBE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / "probe.c", root / "probe"
            source.write_text(source_text)
            for group, compiler in enumerate(("clang", "gcc")):
                bound = binding("ct_eq_128", suite="nix")
                subprocess.run(
                    [
                        shutil.which(compiler),
                        "-O2",
                        "-std=c11",
                        "-D_GNU_SOURCE=1",
                        "-DAEGAEON_DUDECT_CANDIDATE=1",
                        f"-DEXCEPTION_CLASS={group}",
                        '-DAEGAEON_DUDECT_SUITE="nix"',
                        "-I",
                        str(ROOT / "c"),
                        str(source),
                        "-lm",
                        "-o",
                        str(binary),
                        *[
                            f'-DAEGAEON_DUDECT_{key.upper()}="{bound[key]}"'
                            for key in ("build_sha256", "contract_sha256", "numerical_sha256")
                        ],
                    ],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
                for profile in CANDIDATE_PROFILES:
                    bound["profile"] = profile
                    path = root / "native.timing"
                    with path.open("wb") as stream:
                        result = subprocess.run(
                            [str(binary), profile],
                            input=b"c" * 8,
                            env={**os.environ, TIMING_ENV: str(stream.fileno())},
                            pass_fds=(stream.fileno(),),
                            check=True,
                            capture_output=True,
                            timeout=90,
                        )
                    rows = [json.loads(line) for line in result.stdout.splitlines()]
                    admission = CandidateAdmission("ct_eq_128", profile, binding=bound)
                    for row in rows:
                        decision = admission.admit(row)
                    self.assertEqual(
                        decision["candidate_statistical_outcome"],
                        "no_leakage_detected_within_budget",
                    )
                    expected = single_outlier_tail(rows[-1]["statistics"][0][:2], group)
                    self.assertEqual(decision["tests"][0]["p_exact"], list(expected))
                    checked = validate_timing(
                        path, {"ct_eq_128": bound}, profile, {"ct_eq_128": rows}
                    )
                    self.assertEqual(
                        checked["single_outlier_certificates_checked"],
                        102 * sum(batch >= 11 for batch in CANDIDATE_PROFILES[profile][0]),
                    )
                    # Other statistics still rely on the one-outlier certificate;
                    # a changed original sample invalidates them, even with a new hash.
                    with path.open("r+b") as trace:
                        trace.seek(
                            200 + 112 + 11 * (144 + BATCH_SIZE * 9) + 144 + (16739 + group) * 8
                        )
                        old_tick = struct.unpack("<q", trace.read(8))[0]
                        trace.seek(-8, 1)
                        trace.write(struct.pack("<q", old_tick + 1))
                    with self.assertRaisesRegex(ValueError, "differs from original"):
                        validate_timing(path, {"ct_eq_128": bound}, profile, {"ct_eq_128": rows})
        self.assertNotEqual(
            NUMERICAL_SHA256, "ff0c53a9b2fd02566e98390011dc131bb834ec66033892def3217658492c1340"
        )


if __name__ == "__main__":
    unittest.main()
