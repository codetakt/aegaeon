# ruff: noqa: PT009, PT027, S603 - unittest assertions and fixed compiler arguments
"""Reject impossible moments without rejecting rounded native Welford output."""

from __future__ import annotations

import itertools
import math
import shutil
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

from test_dudect_candidate import binding, observation, support

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_candidate import CandidateAdmission
from dudect_support import MAX_SUPPORT_COUNT, class_support

ROOT = Path(__file__).resolve().parents[2]

NATIVE = r"""
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
uint8_t do_one_computation(uint8_t *data) { (void)data; abort(); }
void prepare_inputs(dudect_config_t *c, uint8_t *d, uint8_t *labels) {
    (void)c; (void)d; (void)labels; abort();
}
int main(void) {
    const double bases[] = {0, 100, 0x1p52, 0x1p62, 0x1p110};
    const double steps[] = {1, 0.125, 1, 2048, 0x1p60};
    for (size_t mode = 0; mode < 5; ++mode) {
        ttest_ctx_t state = {0};
        double lo = INFINITY, hi = 0;
        for (size_t i = 0; i < PROBE_COUNT; ++i) {
            double x = bases[mode] + steps[mode] * ((i * 17) % 29);
            if (x < lo) lo = x;
            if (x > hi) hi = x;
            t_push(&state, x, 0);
            if (i == 1 || i == 2 || i == 9 || i == 100002 || i+1 == PROBE_COUNT)
                printf("%zu %a %a %a %a\n", i+1, lo, hi, state.mean[0], state.m2[0]);
        }
    }
    return 0;
}
"""


class MomentSupportTests(unittest.TestCase):
    def admit(self, n, low, high, mean, m2):
        # Integer extrema are checked separately from transformed-value moments.
        class_support(support(n, 0, 100, low, high), n, mean, m2)

    def test_small_integer_samples_against_exact_rational_moments(self):
        for size in range(2, 6):
            for values in itertools.product((0, 1, 4), repeat=size):
                mean = Fraction(sum(values), size)
                m2 = sum((Fraction(x) - mean) ** 2 for x in values)
                self.admit(size, min(values), max(values), float(mean), float(m2))

    def test_extrema_must_be_attainable_at_the_reported_mean(self):
        for mean in (0.1, 9.9):
            with self.assertRaisesRegex(ValueError, "Mean contradicts attained extrema"):
                self.admit(5, 0, 10, mean, 10)

    def test_impossible_upper_and_lower_variance_fail_before_inference(self):
        for index in (0, 50, 101):
            for m2 in (1, 1e20):
                data = observation()
                data["statistics"][index][4] = m2
                with (
                    patch.object(CandidateAdmission, "statistics", side_effect=AssertionError),
                    self.assertRaisesRegex(ValueError, "Squared deviations contradict"),
                ):
                    CandidateAdmission("compare", "pr", binding=binding()).admit(data)

    def test_mean_dependent_upper_bound_is_tighter_than_range_alone(self):
        # With mean 1 in [0, 10], M2 <= 9*n, not the range-only 25*n bound.
        with self.assertRaisesRegex(ValueError, "Squared deviations contradict"):
            self.admit(20001, 0, 10, 1, 10 * 20001)

    def test_rounding_allowance_does_not_clamp_or_rescale_moments(self):
        for value in (math.nextafter(2, 0), 2, math.nextafter(2, math.inf)):
            self.admit(2, 0, 2, 1, value)
        for value in (1.99, 2.01):
            with self.assertRaisesRegex(ValueError, "Squared deviations contradict"):
                self.admit(2, 0, 2, 1, value)
        with self.assertRaisesRegex(ValueError, "measurement budget"):
            self.admit(MAX_SUPPORT_COUNT + 1, 0, 2, 1, 2)

    def test_real_native_welford_at_small_counts_large_offsets_and_scales(self):
        with tempfile.TemporaryDirectory() as directory:
            source, binary = Path(directory) / "moments.c", Path(directory) / "moments"
            source.write_text(NATIVE)
            subprocess.run(
                [
                    shutil.which("cc"),
                    "-O2",
                    f"-DPROBE_COUNT={MAX_SUPPORT_COUNT}",
                    "-I",
                    str(ROOT / "c"),
                    str(source),
                    "-lm",
                    "-o",
                    str(binary),
                ],
                capture_output=True,
                check=True,
                timeout=30,
            )
            result = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=True, timeout=30
            )
            rows = result.stdout.splitlines()
            self.assertEqual(len(rows), 25)
            for row in rows:
                n, *values = row.split()
                self.admit(int(n), *(float.fromhex(value) for value in values))


if __name__ == "__main__":
    unittest.main()
