# ruff: noqa: PT009, S603 - fixed native compiler and synthetic fixture
"""Exercise real batch recording without running a statistical gate."""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dudect_fixture import ROOT
from dudect_timing import BATCH, CASE, TIMING_ENV, validate_timing
from test_dudect_candidate import binding

PROBE = r"""
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
static uint8_t fixed;
uint8_t do_one_computation(uint8_t *data) { return *data; }
void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; ++i) {
        classes[i] = i % 2;
        for (size_t j = 0; j < c->chunk_size; ++j)
            data[i * c->chunk_size + j] = classes[i] ? (uint8_t)(i + j) : fixed;
    }
}
int main(void) {
    const char *names[] = {"compare_product_32", "ct_eq_128", "sha256", "hmac_sha256"};
    const size_t strides[] = {32, 128, 32, 32};
    const uint8_t values[] = {0, 0, 0xAA, 0xBB};
    for (size_t n = 0; n < 4; ++n) {
        fixed = values[n];
        dudect_config_t config = {strides[n], 128}; dudect_ctx_t ctx;
        dudect_init(&ctx, &config);
        dudect_trace_t trace = dudect_trace_begin(names[n], &ctx);
        for (size_t batch = 0; batch < 2; ++batch) {
            dudect_collect(&ctx);
            dudect_trace_batch(&trace, &ctx, batch);
            printf("{\"ticks\":[");
            for (size_t i = 0; i < 128; ++i)
                printf("%s%" PRId64, i ? "," : "", ctx.ticks[i]);
            printf("],\"inputs\":\"");
            for (size_t i = 0; i < 128; ++i)
                for (size_t j = 0; j < 32; ++j)
                    printf("%02x", ctx.input_data[i * config.chunk_size + j]);
            printf("\",\"layout\":[%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR "]}\n",
                   (uintptr_t)ctx.input_data % 4096, (uintptr_t)ctx.ticks % 4096,
                   (uintptr_t)ctx.classes % 4096);
        }
        dudect_trace_end(&trace); dudect_free(&ctx);
    }
    return 0;
}
"""


class NativeTimingTests(unittest.TestCase):
    def test_original_ticks_pilot_context_and_multiple_cases_are_retained(self):
        names = ("compare_product_32", "ct_eq_128", "sha256", "hmac_sha256")
        bindings = {name: binding(name) for name in names}
        fixed = next(iter(bindings.values()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary, trace = root / "probe.c", root / "probe", root / "timing"
            source.write_text(PROBE)
            for compiler in ("clang", "gcc"):
                with self.subTest(compiler=compiler):
                    command = [
                        shutil.which(compiler),
                        "-std=c11",
                        "-O2",
                        "-D_GNU_SOURCE=1",
                        "-DAEGAEON_DUDECT_CANDIDATE=1",
                        '-DAEGAEON_DUDECT_SUITE="legacy"',
                        "-I",
                        str(ROOT / "c"),
                        str(source),
                        "-lm",
                        "-o",
                        str(binary),
                        *[
                            f'-DAEGAEON_DUDECT_{key.upper()}="{fixed[key.lower()]}"'
                            for key in ("BUILD_SHA256", "CONTRACT_SHA256", "NUMERICAL_SHA256")
                        ],
                    ]
                    subprocess.run(command, capture_output=True, check=True, timeout=30)
                    with trace.open("wb") as output:
                        env = {**os.environ, TIMING_ENV: str(output.fileno())}
                        env.pop("AEGAEON_DUDECT_TRACE_FD", None)
                        result = subprocess.run(
                            [str(binary)],
                            env=env,
                            pass_fds=(output.fileno(),),
                            capture_output=True,
                            check=True,
                            timeout=30,
                        )
                    with (
                        patch("dudect_timing.BATCH_SIZE", 128),
                        patch.dict("dudect_timing.PROFILES", {"pr": ((1,), 1, 1)}),
                    ):
                        self.assertTrue(validate_timing(trace, bindings, "pr")["complete"])
                    original = [json.loads(line) for line in result.stdout.splitlines()]
                    self.assert_frames(trace, names, original)
                    # Existing bytes must never be silently appended as a fresh run.
                    with trace.open("ab") as output:
                        rejected = subprocess.run(
                            [str(binary)],
                            env={**env, TIMING_ENV: str(output.fileno())},
                            pass_fds=(output.fileno(),),
                            capture_output=True,
                            check=False,
                            timeout=30,
                        )
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(b"empty timing evidence file", rejected.stderr)

    def assert_frames(self, trace, names, original):
        with trace.open("rb") as data:
            data.seek(200)
            for case, name in enumerate(names):
                recorded_name, stride, width, *layout = CASE.unpack(data.read(CASE.size))
                self.assertEqual(recorded_name.rstrip(b"\0"), name.encode())
                self.assertEqual(stride, 128 if name == "ct_eq_128" else 32)
                self.assertEqual(width, 32 if case >= 2 else 0)
                for batch in range(2):
                    expected = original[case * 2 + batch]
                    self.assertEqual(layout, expected["layout"])
                    frame = BATCH.unpack(data.read(BATCH.size))
                    self.assertGreater(frame[3], frame[2])
                    self.assertIn(frame[4], os.sched_getaffinity(0))
                    self.assertIn(frame[5], os.sched_getaffinity(0))
                    ticks = struct.unpack("<128q", data.read(128 * 8))
                    self.assertEqual(list(ticks), expected["ticks"])
                    self.assertEqual(data.read(128), bytes([0, 1] * 64))
                    if width:
                        inputs = data.read(128 * width)
                        self.assertEqual(inputs, bytes.fromhex(expected["inputs"]))
                        for i in range(128):
                            wanted = (
                                bytes((i + j) % 256 for j in range(32))
                                if i % 2
                                else bytes([0xAA if name == "sha256" else 0xBB]) * 32
                            )
                            self.assertEqual(inputs[i * width : (i + 1) * width], wanted)
            self.assertEqual(data.read(1), b"")


if __name__ == "__main__":
    unittest.main()
