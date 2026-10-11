# ruff: noqa: PT009, PT027, S603 - unittest controls and fixed native compiler argv
"""Candidate observations cannot convert historical failures or admit a gate."""

from __future__ import annotations

import copy
import io
import itertools
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_candidate import (
    ALPHA,
    CANDIDATE_CASES,
    COLLECTION_COMPLETE,
    NUMERICAL_SHA256,
    CandidateAdmission,
    CandidateStream,
    validate_candidate_report,
)
from dudect_results import BATCH_SIZE, PROFILES, CaseAdmission, validate_report

ROOT = Path(__file__).resolve().parents[2]


def binding(name="compare", profile="pr", suite="legacy"):
    return {
        "case_id": f"{suite}/{name}",
        "profile": profile,
        "contract_sha256": "a" * 64,
        "build_sha256": "b" * 64,
        "numerical_sha256": NUMERICAL_SHA256,
    }


def support(count, low, high, vmin, vmax):
    return {
        "count": count,
        "tick_min": low,
        "tick_max": high,
        "value_min_hex": float(vmin).hex(),
        "value_max_hex": float(vmax).hex(),
    }


def observation(name="compare", profile="pr", look=1, *, effect=False, constant=False):
    suite = "legacy" if name in CANDIDATE_CASES["legacy"] else "nix"
    if "/" in name:
        suite, name = name.split("/", 1)
    batches = PROFILES[profile][0][look - 1]
    total = batches * (BATCH_SIZE - 11)
    n0, n1 = total // 2, total - total // 2
    low, high = (62, 62) if constant else (90, 110)
    means = [62, 62] if constant else [103 if effect else 100, 100]
    m2 = [0, 0] if constant else [(n0 - 1) * 9, (n1 - 1) * 9]
    stats = [[n0, n1, *means, *m2] for _ in range(102)]
    pairs = [
        [support(n0, low, high, low, high), support(n1, low, high, low, high)] for _ in range(102)
    ]
    stats[-1][2:4] = [1444, 1444] if constant else [9, 9]
    pairs[-1] = [
        support(n, low, high, 1444 if constant else 0, 1444 if constant else 100) for n in (n0, n1)
    ]
    prepared = (batches + 1) * BATCH_SIZE // 2
    return {
        "schema_version": 4,
        "case": name,
        "profile": profile,
        "binding": binding(name, profile, suite),
        "batch_size": BATCH_SIZE,
        "batches": batches,
        "look": look,
        "executed": prepared * 2,
        "warmup": BATCH_SIZE,
        "rejected": 0,
        "pilot": {"count": 65525, "center": 100, "cutoffs": [200] * 100},
        "statistics": stats,
        "support": pairs,
        "input_audit": {
            "class_count": [prepared, prepared],
            "key_excluded": [0, 0],
            "key_draws": [prepared, prepared] if name.endswith("key_reject") else [0, 0],
        },
    }


def report(profile="pr", suite="legacy"):
    names = CANDIDATE_CASES[suite]
    expected = {
        "bindings": {name: binding(name, profile, suite) for name in names},
        "binaries": {
            name: {"sha256": "c" * 64, "path": "/fixture/" + name, "build_sha256": "b" * 64}
            for name in names
        },
    }
    return {
        "schema_version": 4,
        "suite": suite,
        "profile": profile,
        "outcome": COLLECTION_COMPLETE,
        "admission": "inactive",
        **expected,
        "cases": {
            name: [
                observation(f"{suite}/{name}", profile, look, effect=look == 1)
                for look in range(1, len(PROFILES[profile][0]) + 1)
            ]
            for name in names
        },
    }, copy.deepcopy(expected)


NATIVE = r"""
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
uint8_t do_one_computation(uint8_t *data) { (void)data; abort(); }
void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    (void)c; (void)data; (void)classes; abort();
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int mode = atoi(argv[1]);
    dudect_config_t config = {1, 65536};
    dudect_ctx_t ctx; dudect_init(&ctx, &config);
    ctx.pilot_center = mode == 2 ? 9007199254740992.0 : 63;
    ctx.pilot_count = 65525;
    for (size_t i = 0; i < 100; ++i)
        ctx.percentiles[i] = mode == 2 ? INT64_C(9007199254740996) : 66;
    dudect_input_classes[0] = dudect_input_classes[1] = 32768;
    for (size_t i = 0; i < 65536; ++i) {
        ctx.classes[i] = i % 2;
        ctx.exec_times[i] = mode == 2 ? INT64_C(9007199254740992) + ctx.classes[i]
            : mode == 1 ? 62 + 2 * ctx.classes[i] : 62;
    }
    /* Excluded prefix and uninitialized tail must not reach support. */
    for (size_t i = 0; i < 10; ++i) ctx.exec_times[i] = INT64_MAX;
    ctx.exec_times[65535] = INT64_MAX;
    for (size_t batch = 1; batch <= 7; ++batch) {
        update_statistics(&ctx);
        dudect_input_classes[0] += 32768; dudect_input_classes[1] += 32768;
        dudect_print_candidate("compare", "pr", &ctx, batch, batch);
    }
    dudect_free(&ctx); return 0;
}
"""


class CandidateTests(unittest.TestCase):
    def test_all_cases_both_profiles_keep_detected_differences(self):
        self.assertEqual(sum(map(len, CANDIDATE_CASES.values())), 21)
        self.assertEqual(ALPHA, 0.01 / (21 * 102 * 8))
        for profile in PROFILES:
            for suite in CANDIDATE_CASES:
                data, expected = report(profile, suite)
                decisions = validate_candidate_report(data, expected)
                self.assertTrue(
                    all(d["candidate_statistical_outcome"] == "leakage_detected" for d in decisions)
                )
                self.assertEqual(
                    sum(d["collection_complete"] for d in decisions), len(CANDIDATE_CASES[suite])
                )
                self.assertTrue(all(d["admission"] == "inactive" for d in decisions))
                with self.assertRaises(ValueError):
                    validate_report(data)

    def test_constant_native_support_uses_exact_conditional_permutation(self):
        admission = CandidateAdmission("compare", "pr", binding=binding())
        for look in range(1, 8):
            result = admission.admit(observation(look=look, constant=True))
        self.assertEqual(
            result["candidate_statistical_outcome"], "no_leakage_detected_within_budget"
        )
        self.assertEqual(result["identical_native_tick_candidates"], list(range(102)))
        self.assertTrue(all(test["eligible"] and test["p"] == 1.0 for test in result["tests"]))

    def test_exact_constant_permutation_tail_and_sparse_exclusion(self):
        # Enumerate every label assignment, using integer arithmetic independent
        # of the admission calculation (including values beyond binary64).
        for value in (0, 62, 2**53 + 1):
            for left, right in itertools.product(range(1, 5), repeat=2):
                samples = [value] * (left + right)
                differences = [
                    abs(
                        sum(samples[i] for i in assignment) * right
                        - sum(samples[i] for i in range(left + right) if i not in assignment) * left
                    )
                    for assignment in itertools.combinations(range(left + right), left)
                ]
                self.assertTrue(all(difference == 0 for difference in differences))
        data = observation(constant=True)
        for index in range(1, 101):
            data["statistics"][index][:2] = [10000, 10000]
            for item in data["support"][index]:
                item["count"] = 10000
        result = CandidateAdmission("compare", "pr", binding=binding()).admit(data)
        self.assertTrue(all(not t["eligible"] for t in result["tests"][1:101]))

    def test_native_support_rounding_and_square_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            source, binary = Path(directory) / "probe.c", Path(directory) / "probe"
            source.write_text(NATIVE)
            args = [
                shutil.which("cc"),
                "-O2",
                "-std=c11",
                "-D_GNU_SOURCE=1",
                "-I",
                str(ROOT / "c"),
                "-DAEGAEON_DUDECT_CANDIDATE=1",
                f'-DAEGAEON_DUDECT_NUMERICAL_SHA256="{NUMERICAL_SHA256}"',
                '-DAEGAEON_DUDECT_SUITE="legacy"',
                '-DAEGAEON_DUDECT_CONTRACT_SHA256="' + "a" * 64 + '"',
                '-DAEGAEON_DUDECT_BUILD_SHA256="' + "b" * 64 + '"',
                str(source),
                "-lm",
                "-o",
                str(binary),
            ]
            subprocess.run(args, capture_output=True, check=True, timeout=30)
            for mode in range(3):
                proc = subprocess.run(
                    [str(binary), str(mode)], capture_output=True, check=True, timeout=30
                )
                stream = CandidateStream(("compare",), "pr", bindings={"compare": binding()})
                acknowledgments = io.BytesIO()
                stream.consume(proc.stdout, acknowledgments)
                stream.finish(0)
                final = stream.decisions[-1]
                self.assertEqual(
                    final["candidate_statistical_outcome"],
                    "inconclusive" if mode else "no_leakage_detected_within_budget",
                )
                self.assertEqual(
                    final["identical_native_tick_candidates"], [] if mode else list(range(102))
                )
                self.assertEqual(acknowledgments.getvalue(), b"c" * 7)

    def test_native_crop_includes_the_entire_integer_boundary(self):
        # Both classes have only the boundary tick. Strict < used to empty all
        # crops even though the empirical quantile contains the entire sample.
        probe = NATIVE.replace("main(int argc, char **argv)", "unused_main(int argc, char **argv)")
        probe += r"""
int main(void) {
    dudect_config_t config = {1, 65536};
    dudect_ctx_t ctx; dudect_init(&ctx, &config);
    for (size_t i = 0; i < 65536; ++i) {
        ctx.classes[i] = i % 2;
        ctx.exec_times[i] = 62;
    }
    prepare_percentiles(&ctx);
    ctx.pilot_center = 62;
    for (size_t i = 0; i < 65536; ++i) ctx.exec_times[i] = 62;
    update_statistics(&ctx);
    for (size_t i = 1; i <= 100; ++i) {
        if (ctx.percentiles[i - 1] != 62) return 1;
        for (size_t group = 0; group < 2; ++group) {
            if (ctx.ttest_ctxs[i]->support[group].count !=
                ctx.ttest_ctxs[0]->support[group].count) return 2;
        }
    }
    dudect_free(&ctx); return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            source, binary = Path(directory) / "probe.c", Path(directory) / "probe"
            source.write_text(probe)
            args = [
                shutil.which("cc"),
                "-O2",
                "-std=c11",
                "-D_GNU_SOURCE=1",
                "-I",
                str(ROOT / "c"),
                "-DAEGAEON_DUDECT_CANDIDATE=1",
                f'-DAEGAEON_DUDECT_NUMERICAL_SHA256="{NUMERICAL_SHA256}"',
                '-DAEGAEON_DUDECT_SUITE="legacy"',
                '-DAEGAEON_DUDECT_CONTRACT_SHA256="a"',
                '-DAEGAEON_DUDECT_BUILD_SHA256="b"',
                str(source),
                "-lm",
                "-o",
                str(binary),
            ]
            subprocess.run(args, capture_output=True, check=True, timeout=30)
            subprocess.run([str(binary)], capture_output=True, check=True, timeout=10)

    def test_missing_new_case_or_changed_binary_cannot_complete(self):
        data, expected = report()
        data["cases"].pop("hmac_key_reject")
        with self.assertRaises(ValueError):
            validate_candidate_report(data, expected)
        data, expected = report()
        data["binaries"]["hmac"]["sha256"] = "d" * 64
        with self.assertRaises(ValueError):
            validate_candidate_report(data, expected)

    def test_every_identity_and_schema_is_required(self):
        for key in binding():
            data = observation()
            data["binding"][key] = "wrong"
            with self.assertRaises(ValueError):
                CandidateAdmission("compare", "pr", binding=binding()).admit(data)
        prior = observation()
        prior["schema_version"] = 3
        with self.assertRaises(ValueError):
            CandidateAdmission("compare", "pr", binding=binding()).admit(prior)
        old = observation()
        for key in ("binding", "support", "input_audit"):
            old.pop(key)
        old["schema_version"] = 2
        CaseAdmission("compare", "pr").admit(old)
        with self.assertRaises(ValueError):
            CandidateAdmission("compare", "pr", binding=binding()).admit(old)

    def test_tampered_support_and_input_audit_fail_closed(self):
        changes = [
            lambda d: d["support"].pop(),
            lambda d: d["support"][0][0].update(count=True),
            lambda d: d["support"][0][0].update(tick_min=-1),
            lambda d: d["support"][0][0].update(tick_max=2**63),
            lambda d: d["support"][0][0].update(value_min_hex="nan"),
            lambda d: d["support"][0][0].update(value_max_hex="0x1p+99999"),
            lambda d: d["support"][0][0].update(value_min_hex="0x1p+0"),
            lambda d: d["input_audit"]["class_count"].__setitem__(0, 0),
            lambda d: d["input_audit"]["key_excluded"].__setitem__(0, 1),
            lambda d: d["input_audit"]["key_draws"].__setitem__(1, 1),
        ]
        for change in changes:
            data = observation("hmac_key_reject")
            change(data)
            with self.assertRaises(ValueError):
                CandidateAdmission(
                    "hmac_key_reject", "pr", binding=binding("hmac_key_reject")
                ).admit(data)

    def test_native_support_cannot_shrink_between_looks(self):
        admission = CandidateAdmission("compare", "pr", binding=binding())
        admission.admit(observation())
        data = observation(look=2)
        data["support"][0][0].update(tick_min=91, value_min_hex=float(91).hex())
        with self.assertRaisesRegex(ValueError, "minimum increased"):
            admission.admit(data)

    def test_partial_and_extra_schedules_cannot_complete(self):
        data, expected = report()
        data["cases"]["compare"].pop()
        with self.assertRaises(ValueError):
            validate_candidate_report(data, expected)
        data, expected = report()
        data["cases"]["jwe_key_reject"].append(data["cases"]["jwe_key_reject"][-1])
        with self.assertRaises(ValueError):
            validate_candidate_report(data, expected)

    def test_malformed_report_envelopes_fail_closed(self):
        for key in ("suite", "profile", "bindings", "binaries", "cases"):
            data, expected = report()
            data[key] = []
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_candidate_report(data, expected)
        for key in ("case_id", "contract_sha256", "build_sha256"):
            data = observation()
            expected = binding()
            expected[key] = data["binding"][key] = "unbound"
            with self.subTest(key=key), self.assertRaises(ValueError):
                CandidateAdmission("compare", "pr", binding=expected).admit(data)


if __name__ == "__main__":
    unittest.main()
