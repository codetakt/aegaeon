# ruff: noqa: PT009, PT027, S603 - deterministic native fixture, explicit compiler argv
"""Known native signals and deliberately broken controls exercise the actual role gate."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_candidate import NUMERICAL_SHA256, CandidateAdmission, significant
from dudect_contract import ObservationError, assess_case

ROOT = Path(__file__).resolve().parents[2]


class DetectorIntegrityTests(unittest.TestCase):
    def test_known_native_signals_and_faults_reach_the_specified_role(self):
        for compiler in ("gcc", "clang"):
            self.assertIsNotNone(shutil.which(compiler), compiler)
            with self.subTest(compiler=compiler), tempfile.TemporaryDirectory() as directory:
                binary = Path(directory) / "known-signals"
                subprocess.run(
                    [
                        compiler,
                        "-O2",
                        "-std=c11",
                        "-D_GNU_SOURCE=1",
                        "-DAEGAEON_DUDECT_CANDIDATE=1",
                        '-DAEGAEON_DUDECT_SUITE="legacy"',
                        '-DAEGAEON_DUDECT_CONTRACT_SHA256="' + "a" * 64 + '"',
                        '-DAEGAEON_DUDECT_BUILD_SHA256="' + "b" * 64 + '"',
                        f'-DAEGAEON_DUDECT_NUMERICAL_SHA256="{NUMERICAL_SHA256}"',
                        "-I",
                        str(ROOT / "c"),
                        str(ROOT / "tests/ci/fixtures/dudect_known_signals.c"),
                        "-lm",
                        "-o",
                        str(binary),
                    ],
                    check=True,
                    capture_output=True,
                    timeout=60,
                )
                for fault in range(5):
                    with self.subTest(fault=fault):
                        result = subprocess.run(
                            [str(binary), str(fault)],
                            input="c" * 24,
                            text=True,
                            capture_output=True,
                            check=True,
                            timeout=60,
                        )
                        rows = [json.loads(line) for line in result.stdout.splitlines()]
                        self.assertEqual(len(rows), 24)
                        for start in range(0, 24, 8):
                            chunk = rows[start : start + 8]
                            name = chunk[0]["case"]
                            admission = CandidateAdmission(name, "pr", binding=chunk[0]["binding"])
                            history = [admission.admit(row) for row in chunk]
                            role = (
                                "measurement_negative_control"
                                if start == 0
                                else "measurement_positive_control"
                            )
                            fails = (
                                fault == 4
                                or (fault == 1 and start == 8)
                                or (fault == 2 and start == 16)
                                or (fault == 3 and start == 0)
                            )
                            if fails:
                                with self.assertRaises(ObservationError):
                                    assess_case("legacy/" + name, role, history, "pr")
                            else:
                                self.assertTrue(
                                    assess_case("legacy/" + name, role, history, "pr")[
                                        "requirement_satisfied"
                                    ]
                                )
                            if fault == 0 and start:
                                statistic = 0 if start == 8 else 101
                                self.assertTrue(
                                    any(significant(h["tests"][statistic]) for h in history)
                                )


if __name__ == "__main__":
    unittest.main()
