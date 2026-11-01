# ruff: noqa: PT009, PT027, S603 - compile and execute a bounded diagnostic fixture
"""Retain and validate each actual control input outside statistical admission."""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_dudect_candidate import binding

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/constant_time"))
from dudect_timing import (  # noqa: E402 - source-specific helper imports
    BATCH,
    CASE_V4,
    TIMING_ENV,
    validate_control_inputs,
    validate_timing,
)

PROBE = r"""
#define main control_main
#include "tests/constant_time/calibration_timing_test.c"
#undef main
int main(void) {
    const char *names[] = {"control_independent", "control_mean_shift", "control_variance_shift"};
    for (control = 0; control < 3; ++control) {
        dudect_config_t config = {sizeof(uint32_t), 128}; dudect_ctx_t ctx;
        dudect_init(&ctx, &config);
        dudect_trace_t trace = dudect_trace_begin(names[control], &ctx);
        for (size_t batch = 0; batch < 2; ++batch) {
            dudect_collect(&ctx);
            dudect_trace_batch(&trace, &ctx, batch);
            printf("[");
            for (size_t i = 0; i < 128; ++i) {
                uint32_t input; memcpy(&input, ctx.input_data + i * sizeof input, sizeof input);
                printf("%s%u", i ? "," : "", input);
            }
            puts("]");
        }
        dudect_trace_end(&trace); dudect_free(&ctx);
    }
    return 0;
}
"""


class DudectControlInputTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_native_control_bytes_roundtrip_and_invalid_inputs_rejected(self):
        for compiler in ("gcc", "clang"):
            with self.subTest(compiler=compiler):
                self.check_native_control_bytes(self.root, compiler)

    def test_control_domains_include_original_bounds_and_reject_class_confusion(self):
        for name, values in (
            ("control_independent", (256, 287)),
            ("control_mean_shift", (287, 320)),
            ("control_variance_shift", (2048, 1024)),
            ("control_variance_shift", (2079, 3103)),
        ):
            with self.subTest(name=name, values=values):
                self.check_control_domain(name, values)

    def check_native_control_bytes(self, tmp_path, compiler):
        bound = binding("control_independent")
        source, binary, timing = tmp_path / "probe.c", tmp_path / "probe", tmp_path / "timing"
        source.write_text(PROBE)
        command = [
            shutil.which(compiler),
            "-std=c11",
            "-O2",
            "-D_GNU_SOURCE=1",
            "-DAEGAEON_DUDECT_CANDIDATE=1",
            '-DAEGAEON_DUDECT_SUITE="legacy"',
            "-I",
            str(ROOT),
            "-I",
            str(ROOT / "c"),
            str(source),
            "-lm",
            "-o",
            str(binary),
        ]
        command += [
            f'-DAEGAEON_DUDECT_{key.upper()}="{bound[key]}"'
            for key in ("build_sha256", "contract_sha256", "numerical_sha256")
        ]
        subprocess.run(command, capture_output=True, check=True, timeout=30)
        with timing.open("wb") as output:
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                check=True,
                timeout=30,
                env={**os.environ, TIMING_ENV: str(output.fileno())},
                pass_fds=(output.fileno(),),
            )
        inputs = [json.loads(line) for line in result.stdout.splitlines()]
        names = ("control_independent", "control_mean_shift", "control_variance_shift")
        with (
            patch("dudect_timing.BATCH_SIZE", 128),
            patch.dict("dudect_timing.PROFILES", {"pr": ((1,), 1, 1)}),
        ):
            summary = validate_timing(timing, dict.fromkeys(names, bound), "pr")
            self.assertEqual(summary["format"], "AEGTIM05")
            self.assertEqual(summary["input_cases"], list(names))
            data = bytearray(timing.read_bytes())
            offset = 200
            for case in range(3):
                self.assertEqual(CASE_V4.unpack_from(data, offset)[1:3], (4, 4))
                offset += CASE_V4.size
                for batch in range(2):
                    offset += BATCH.size + 128 * 9
                    self.assertEqual(
                        list(struct.unpack_from("<128I", data, offset)), inputs[case * 2 + batch]
                    )
                    offset += 128 * 4
            first_input = 200 + CASE_V4.size + BATCH.size + 128 * 9
            struct.pack_into("<I", data, first_input, 0)
            timing.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "control iteration"):
                validate_timing(timing, dict.fromkeys(names, bound), "pr")

    def check_control_domain(self, name, values):
        payload = struct.pack("<2I", *values)
        validate_control_inputs(payload, bytes([0, 1]), name)
        if name != "control_independent":
            with self.assertRaisesRegex(ValueError, "control iteration"):
                validate_control_inputs(payload, bytes([1, 0]), name)
