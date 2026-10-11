# ruff: noqa: PT009, S603 - unittest assertions and fixed native compiler argv
"""Exercise the actual C collector with deterministic observations and a real pilot."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = r"""
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
uint8_t do_one_computation(uint8_t *data) { return *data; }
void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    memset(data, 1, c->number_measurements * c->chunk_size);
    for (size_t i = 0; i < c->number_measurements; ++i) classes[i] = i % 2;
}
int main(void) {
    dudect_config_t config = {1, 128};
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    dudect_collect(&ctx);
    if (ctx.batches != 1 || ctx.ttest_ctxs[0]->n[0] || ctx.ttest_ctxs[0]->n[1]) return 1;
    if (!ctx.pilot_count || ctx.pilot_count > 117) return 2;
    ctx.pilot_center = 120;
    for (size_t i = 0; i < DUDECT_NUMBER_PERCENTILES; ++i) ctx.percentiles[i] = 10000;
    for (size_t i = 0; i < 128; ++i) ctx.exec_times[i] = 100 + i;
    ctx.exec_times[10] = -1;
    update_statistics(&ctx);
    if (ctx.rejected != 1) return 3;
    for (size_t i = 0; i < DUDECT_TESTS; ++i) {
        ttest_ctx_t *test = ctx.ttest_ctxs[i];
        if (test->n[0] + test->n[1] != 116 || test->m2[0] <= 0 || test->m2[1] <= 0) return 4;
    }
    update_statistics(&ctx);
    if (ctx.rejected != 2 || ctx.ttest_ctxs[0]->n[0] + ctx.ttest_ctxs[0]->n[1] != 232) return 5;
    if (ctx.pilot_center != 120 || ctx.percentiles[0] != 10000) return 6;
    for (size_t i = 0; i < 128; ++i) ctx.exec_times[i] = -1;
    prepare_percentiles(&ctx);
    if (ctx.pilot_count != 0) return 7;
    dudect_free(&ctx);
    return 0;
}
"""


class DudectCollectionTests(unittest.TestCase):
    def test_provider_comparison_repeats_reads_in_optimized_loop(self):
        harness = (ROOT / "c/dudect_harness.c").read_text()
        comparator = re.search(r"^static int ct_eq\(.*?^}", harness, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(comparator)
        repeated = harness.split("case TEST_CT_EQ:", 1)[1].split("break;", 1)[0]
        probe = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n"
            "#define CHUNK_LEN 32\nstatic uint8_t secret[CHUNK_LEN];\n"
            + comparator[0]
            + "\nuint8_t comparison_probe(uint8_t *data) { uint8_t result = 0;\n"
            + repeated
            + "\nreturn result; }\n"
            + r"""
int main(void) {
    uint8_t data[CHUNK_LEN + 1];
    const uint8_t patterns[] = {0, 0xa5, 0xff};
    for (size_t pattern = 0; pattern < sizeof patterns; ++pattern) {
        memset(secret, patterns[pattern], sizeof secret);
        memset(data, patterns[pattern], sizeof data);
        if (comparison_probe(data) != 1) return 1;
        for (size_t position = 0; position < CHUNK_LEN; ++position) {
            for (unsigned bit = 0; bit < 8; ++bit) {
                data[position] ^= (uint8_t)(1U << bit);
                if (comparison_probe(data) != 0) return 2;
                data[position] ^= (uint8_t)(1U << bit);
            }
        }
        data[CHUNK_LEN] ^= 0xff;
        if (comparison_probe(data) != 1) return 3;
    }
    return 0;
}
"""
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "comparison.c"
            assembly = Path(directory) / "comparison.s"
            executable = Path(directory) / "comparison"
            source.write_text(probe)
            # Compile the entire real callback for the optimization check.
            # Declarations suffice for -S; no substitute crypto is executed.
            declarations = {
                "Hacl_Ed25519.h": (
                    "#include <stdbool.h>\n"
                    "bool Hacl_Ed25519_verify(uint8_t *, uint32_t, uint8_t *, uint8_t *);\n"
                ),
                "Hacl_HMAC.h": (
                    "void Hacl_HMAC_compute_sha2_256(uint8_t *, uint8_t *, uint32_t, "
                    "uint8_t *, uint32_t);\n"
                ),
                "Hacl_Hash_SHA2.h": (
                    "void Hacl_Hash_SHA2_hash_256(uint8_t *, uint8_t *, uint32_t);\n"
                ),
            }
            for header, declaration in declarations.items():
                (Path(directory) / header).write_text(declaration)
            definitions = [
                f'-DAEGAEON_DUDECT_{field}_SHA256="{"0" * 64}"'
                for field in ("CONTRACT", "BUILD", "NUMERICAL")
            ]
            for name in ("clang", "gcc"):
                with self.subTest(compiler=name):
                    compiler = shutil.which(name)
                    self.assertIsNotNone(compiler)
                    argv = [compiler, "-O2", "-std=c11", "-DAEGAEON_DUDECT_CANDIDATE=1"]
                    commands = [
                        [*argv, str(source), "-o", str(executable)],
                        [
                            *argv,
                            "-D_GNU_SOURCE=1",
                            '-DAEGAEON_DUDECT_SUITE="nix"',
                            *definitions,
                            "-I",
                            directory,
                            str(ROOT / "c/dudect_harness.c"),
                            "-S",
                            "-o",
                            str(assembly),
                        ],
                    ]
                    for command in commands:
                        compiled = subprocess.run(
                            command,
                            capture_output=True,
                            check=False,
                            timeout=30,
                        )
                        self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    result = subprocess.run(
                        [str(executable)], capture_output=True, check=False, timeout=10
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assert_comparison_loop_reads(assembly)

    def assert_comparison_loop_reads(self, assembly):
        body = re.search(
            r"\bdo_one_computation:.*?\.size\s+do_one_computation\b",
            assembly.read_text(),
            re.DOTALL,
        )
        self.assertIsNotNone(body)
        self.assertRegex(body[0], r"\$(?:1000|-1000|4294966296)\b")
        lines = body[0].splitlines()
        initialization = next(
            index
            for index, line in enumerate(lines)
            if re.search(r"\$(?:1000|-1000|4294966296)\b", line)
        )
        labels = {}
        loops = []
        for index, line in enumerate(lines):
            if label := re.match(r"(\.L\w+):", line):
                labels[label[1]] = index
            if (
                (branch := re.match(r"\s+j\w+\s+(\.L\w+)", line))
                and branch[1] in labels
                and labels[branch[1]] > initialization
            ):
                loops.append((labels[branch[1]], index))
        self.assertTrue(loops, "The comparison must remain in a repeated loop")
        first = loops[0]
        enclosing = [loop for loop in loops if loop[0] <= first[0] and loop[1] >= first[1]]
        start, end = max(enclosing, key=lambda loop: loop[1] - loop[0])
        outer = "\n".join(lines[start : end + 1])
        # A 1000-iteration OR of a value computed before the loop
        # is insufficient. Both operands must be read inside it.
        reads = re.findall(
            r"^\s+(?:mov\w*|[vp]?(?:xor|or)\w*)\s+"
            r"[^#\n]*\([^)]+\)[^,\n]*,\s*%",
            outer,
            re.MULTILINE,
        )
        self.assertGreaterEqual(len(reads), 2, outer)

    def test_optimized_candidate_timer_orders_both_sides_of_timestamp(self):
        # Check emitted instructions, not intrinsic spelling: optimization must
        # preserve the SDM ordering in each supported compiler profile.
        probe = PROBE[: PROBE.index("int main(void)")] + (
            "int64_t timer_probe(void) { return cpucycles(); }\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "timer.c"
            assembly = Path(directory) / "timer.s"
            source.write_text(probe)
            for name in ("clang", "gcc"):
                with self.subTest(compiler=name):
                    compiler = shutil.which(name)
                    self.assertIsNotNone(compiler, f"The timer check requires {name}")
                    result = subprocess.run(
                        [
                            compiler,
                            "-O2",
                            "-std=c11",
                            "-D_GNU_SOURCE=1",
                            "-DAEGAEON_DUDECT_CANDIDATE=1",
                            "-I",
                            str(ROOT / "c"),
                            "-S",
                            str(source),
                            "-o",
                            str(assembly),
                        ],
                        capture_output=True,
                        check=False,
                        timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    body = re.search(
                        r"\btimer_probe:.*?\.size\s+timer_probe\b",
                        assembly.read_text(),
                        re.DOTALL,
                    )
                    self.assertIsNotNone(body)
                    instructions = re.findall(r"^\s+(mfence|lfence|rdtsc)\b", body[0], re.MULTILINE)
                    self.assertEqual(instructions, ["mfence", "lfence", "rdtsc", "lfence"])

    def test_warmup_retained_counts_invalid_deltas_and_fixed_center(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "The native collector check requires the pinned C compiler")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "collector.c"
            executable = Path(directory) / "collector"
            source.write_text(PROBE)
            compiled = subprocess.run(
                [compiler, "-O2", "-I", str(ROOT / "c"), str(source), "-lm", "-o", str(executable)],
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
