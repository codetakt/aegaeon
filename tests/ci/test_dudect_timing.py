# ruff: noqa: PT009, S603 - fixed native compiler and synthetic fixture
"""Exercise real batch recording without running a statistical gate."""

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
from pathlib import Path
from unittest.mock import patch

from dudect_fixture import ROOT
from test_dudect_candidate import binding

sys.path.insert(0, str(ROOT / "tests/constant_time"))
from dudect_diagnostics import FRAME, TRACE_ENV, validate_trace
from dudect_timing import BATCH, CASE_V4, INPUTS, TIMING_ENV, summarize_ticks, validate_timing

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
    const char *names[] = {
        "compare_product_32", "ct_eq_128", "sha256", "hmac_sha256", "hmac_sha256_key"
    };
    const size_t strides[] = {32, 128, 32, 32, 32};
    const uint8_t values[] = {0, 0, 0xAA, 0xBB, 0x42};
    for (size_t n = 0; n < 5; ++n) {
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
                for (size_t j = 0; j < config.chunk_size; ++j)
                    printf("%02x", ctx.input_data[i * config.chunk_size + j]);
            printf("\",\"layout\":[%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR "]}\n",
                   (uintptr_t)ctx.input_data % 4096, (uintptr_t)ctx.ticks % 4096,
                   (uintptr_t)ctx.classes % 4096, (uintptr_t)&ctx % 4096);
        }
        dudect_trace_end(&trace); dudect_free(&ctx);
    }
    return 0;
}
"""

SCHEDULE_PROBE = r"""
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
/* Exercise the real producer and trace framing with deterministic samples.
 * Any accidental entry into the real measurement loop must fail. */
uint8_t do_one_computation(uint8_t *data) { (void)data; abort(); }
void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    (void)c; (void)data; (void)classes; abort();
}
static void fixture_collect(dudect_ctx_t *ctx) {
    size_t count = ctx->config->number_measurements;
    ctx->timing_before = dudect_context();
    for (size_t i = 0; i < count; ++i) {
        ctx->classes[i] = i % 2;
        dudect_input_classes[i % 2]++;
        memset(ctx->input_data + i * ctx->config->chunk_size,
               i % 2, ctx->config->chunk_size);
        ctx->ticks[i] = (int64_t)i * 62;
        ctx->exec_times[i] = 62;
    }
    if (ctx->batches == 0) {
        ctx->pilot_center = 62;
        prepare_percentiles(ctx);
    } else update_statistics(ctx);
    ctx->batches++;
    ctx->timing_after = dudect_context();
}
#define dudect_collect fixture_collect
#include "dudect_report.h"
int main(int argc, char **argv) {
    return dudect_run_case("ct_eq_128", 128, argc, argv);
}
"""


class NativeTimingTests(unittest.TestCase):
    def test_native_schedule_retains_uninspected_batches_and_requires_ack(self):
        bound = binding("ct_eq_128", suite="nix")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / "schedule.c", root / "schedule"
            source.write_text(SCHEDULE_PROBE)
            for compiler in ("clang", "gcc"):
                command = [
                    shutil.which(compiler),
                    "-O2",
                    "-std=c11",
                    "-D_GNU_SOURCE=1",
                    "-DAEGAEON_DUDECT_CANDIDATE=1",
                    "-DAEGAEON_DUDECT_BATCH_SIZE=128",
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
                ]
                subprocess.run(command, check=True, capture_output=True, timeout=30)
                for profile, wanted in (
                    ("pr", [1, 2, 3, 4, 5, 6, 7, 16]),
                    ("periodic", [1, 2, 4, 8, 16, 32, 64, 98]),
                ):
                    with self.subTest(compiler=compiler, profile=profile):
                        bound["profile"] = profile
                        timing, samples = root / "timing", root / "samples"
                        with timing.open("wb") as out, samples.open("wb") as ordered:
                            proc = subprocess.run(
                                [str(binary), profile],
                                input=b"c" * 8,
                                env={
                                    **os.environ,
                                    TIMING_ENV: str(out.fileno()),
                                    TRACE_ENV: str(ordered.fileno()),
                                },
                                pass_fds=(out.fileno(), ordered.fileno()),
                                capture_output=True,
                                check=True,
                                timeout=30,
                            )
                        rows = [json.loads(line) for line in proc.stdout.splitlines()]
                        self.assertEqual([row["batches"] for row in rows], wanted)
                        self.assertEqual([row["look"] for row in rows], list(range(1, 9)))
                        self.assertTrue(all(row["pilot"] == rows[0]["pilot"] for row in rows))
                        self.assertEqual(sum(rows[-1]["statistics"][0][:2]), wanted[-1] * 117)
                        with (
                            patch("dudect_timing.BATCH_SIZE", 128),
                            patch("dudect_diagnostics.BATCH_SIZE", 128),
                        ):
                            self.assertTrue(
                                validate_timing(timing, {"ct_eq_128": bound}, profile)["complete"]
                            )
                            self.assertTrue(validate_trace(samples, bound, profile)["complete"])
                        self.assertEqual(
                            timing.stat().st_size,
                            200 + CASE_V4.size + (wanted[-1] + 1) * (BATCH.size + 128 * 9),
                        )
                        self.assertEqual(
                            samples.stat().st_size,
                            200 + (wanted[-1] + 1) * (FRAME.size + 128 * 137),
                        )
                        failed = subprocess.run(
                            [str(binary), profile],
                            input=b"c" * 7,
                            capture_output=True,
                            check=False,
                            timeout=30,
                        )
                        self.assertEqual(failed.returncode, 2)

    def test_original_ticks_pilot_context_and_multiple_cases_are_retained(self):
        names = ("compare_product_32", "ct_eq_128", "sha256", "hmac_sha256", "hmac_sha256_key")
        bindings = {name: binding(name) for name in names}
        fixed = next(iter(bindings.values()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary, trace = root / "probe.c", root / "probe", root / "timing"
            samples = root / "samples"
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
                    with trace.open("wb") as output, samples.open("wb") as ordered:
                        env = {
                            **os.environ,
                            TIMING_ENV: str(output.fileno()),
                            TRACE_ENV: str(ordered.fileno()),
                        }
                        result = subprocess.run(
                            [str(binary)],
                            env=env,
                            pass_fds=(output.fileno(), ordered.fileno()),
                            capture_output=True,
                            check=True,
                            timeout=30,
                        )
                    with (
                        patch("dudect_timing.BATCH_SIZE", 128),
                        patch.dict("dudect_timing.PROFILES", {"pr": ((1,), 1, 1)}),
                        patch("dudect_diagnostics.BATCH_SIZE", 128),
                        patch.dict("dudect_diagnostics.PROFILES", {"pr": ((1,), 1, 1)}),
                    ):
                        summary = validate_timing(trace, bindings, "pr")
                        self.assertTrue(summary["complete"])
                        self.assertEqual(summary["format"], "AEGTIM04")
                        self.assertTrue(
                            validate_trace(samples, bindings["ct_eq_128"], "pr")["complete"]
                        )
                    original = [json.loads(line) for line in result.stdout.splitlines()]
                    self.assertEqual(
                        summary["case_context_offsets_mod4096"],
                        {
                            name: original[index * 2]["layout"][3]
                            for index, name in enumerate(names)
                        },
                    )
                    self.assert_frames(trace, names, original)
                    self.assert_full_sample_frames(samples, original[2:4])
                    # Existing bytes must never be silently appended as a fresh run.
                    with trace.open("ab") as output:
                        env.pop(TRACE_ENV, None)
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

    def assert_full_sample_frames(self, samples, original):
        with samples.open("rb") as data:
            self.assertEqual(data.read(8), b"AEGTRC02")
            data.seek(200)
            for batch, expected in enumerate(original):
                self.assertEqual(FRAME.unpack(data.read(FRAME.size)), (batch, 128, 128, 128))
                self.assertEqual(
                    list(struct.unpack("<128q", data.read(128 * 8))), expected["ticks"]
                )
                self.assertEqual(data.read(128), bytes([0, 1] * 64))
                inputs = data.read(128 * 128)
                self.assertEqual(inputs, bytes.fromhex(expected["inputs"]))
                for i in range(128):
                    wanted = bytes((i + j) % 256 for j in range(128)) if i % 2 else bytes(128)
                    self.assertEqual(inputs[i * 128 : (i + 1) * 128], wanted)
            self.assertEqual(data.read(1), b"")

    def assert_frames(self, trace, names, original):
        with trace.open("rb") as data:
            self.assertEqual(data.read(8), b"AEGTIM04")
            data.seek(200)
            for case, name in enumerate(names):
                recorded_name, stride, width, *layout = CASE_V4.unpack(data.read(CASE_V4.size))
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
                                else bytes([INPUTS[name]]) * 32
                            )
                            self.assertEqual(inputs[i * width : (i + 1) * width], wanted)
            self.assertEqual(data.read(1), b"")

    def test_clock_lattice_keeps_zeros_backwards_and_absolute_phase(self):
        for ticks, gcd, phase, zeros, backwards, low, high in (
            ([7, 33, 85, 85, 59], 26, 7, 1, 1, -26, 52),
            ([7, 9, 13, 19, 27], 2, 1, 0, 0, 2, 8),
            ([7, 7, 7, 7, 7], 0, None, 4, 0, 0, 0),
        ):
            with self.subTest(ticks=ticks), patch("dudect_timing.BATCH_SIZE", len(ticks)):
                clock = summarize_ticks(
                    tuple(ticks), tuple(b - a for a, b in itertools.pairwise(ticks))
                )
                self.assertEqual(
                    clock,
                    {
                        "adjacent_pairs": 4,
                        "delta_min": low,
                        "delta_max": high,
                        "delta_gcd": gcd,
                        "timestamp_residue_mod_gcd": phase,
                        "zero_deltas": zeros,
                        "backward_deltas": backwards,
                    },
                )


if __name__ == "__main__":
    unittest.main()
