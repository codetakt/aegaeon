# ruff: noqa: PT009, PT027, S603
"""Actual trace/ACK integration, independent raw replay and fail-closed limits."""

from __future__ import annotations

import copy
import io
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_candidate import CONTROL_CASES, NUMERICAL_SHA256, canonical
from dudect_contract import ObservationError, assess_case
from dudect_process import ObservationStream, receive, terminate
from dudect_sparse_contract import check_runtime_contract
from dudect_sparse_runtime import PROOF_NAME, PrefixReader, RuntimeStream, Worker, replay_runtime
from dudect_timing import TIMING_ENV

ROOT = Path(__file__).resolve().parents[2]


class RuntimeTests(unittest.TestCase):
    def run_native(self, compiler, rare):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        binding = {
            "case_id": "legacy/compare",
            "profile": "pr",
            "contract_sha256": check_runtime_contract(),
            "numerical_sha256": NUMERICAL_SHA256,
            "build_sha256": "b" * 64,
        }
        binary = directory / "native"
        macros = [
            "-DAEGAEON_DUDECT_CANDIDATE=1",
            '-DAEGAEON_DUDECT_SUITE="legacy"',
            f"-DTEST_MODE={rare}",
        ]
        macros.extend(
            f'-DAEGAEON_DUDECT_{name.upper()}_SHA256="{binding[name + "_sha256"]}"'
            for name in ("contract", "numerical", "build")
        )
        subprocess.run(
            [
                compiler,
                "-O2",
                "-std=c11",
                "-D_GNU_SOURCE=1",
                *macros,
                "-I",
                str(ROOT / "c"),
                str(ROOT / "tests/ci/fixtures/dudect_runtime_signals.c"),
                "-lm",
                "-o",
                str(binary),
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        names = CONTROL_CASES if rare >= 200 else ("compare",)
        bindings = {name: {**binding, "case_id": "legacy/" + name} for name in names}
        stream = RuntimeStream(names, "pr", bindings=bindings)
        with (
            (directory / "native.timing").open("xb") as raw,
            (directory / PROOF_NAME).open("wb") as journal,
            (directory / "native.stdout").open("wb") as out,
            (directory / "stderr").open("wb") as errors,
        ):
            worker = Worker(directory / "native.timing", bindings, errors)
            stream.attach(worker, journal)
            process = subprocess.Popen(
                [str(binary), "pr"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=errors,
                env={**os.environ, TIMING_ENV: str(raw.fileno())},
                pass_fds=(raw.fileno(),),
                start_new_session=True,
            )
            try:
                receive(process, out, stream, time.monotonic() + 60, case_budget=60)
            finally:
                terminate(process)
                worker.close()
        for name, value in (
            ("decisions", stream.decisions),
            ("effective-decisions", stream.effective),
        ):
            (directory / f"{name}.json").write_bytes(canonical(value))
        return directory, binding, stream

    def test_native_sparse_and_out_of_domain_preserve_original_and_replay(self):
        for compiler in ("gcc", "clang"):
            for rare in (2, 3, 4):
                with self.subTest(compiler=compiler, rare=rare):
                    directory, binding, stream = self.run_native(compiler, rare)
                    self.assertEqual(
                        stream.decisions[-1]["candidate_statistical_outcome"], "inconclusive"
                    )
                    expected = "no_leakage_detected_within_budget" if rare < 4 else "inconclusive"
                    self.assertEqual(
                        stream.effective[-1]["candidate_statistical_outcome"], expected
                    )
                    self.assertEqual(
                        replay_runtime(directory, {"compare": binding}, "pr", stream.histories),
                        stream.effective,
                    )
                    if rare < 4:
                        assess_case(
                            "legacy/compare", "measurement_negative_control", stream.effective, "pr"
                        )
                    else:
                        with self.assertRaises(ObservationError):
                            assess_case(
                                "legacy/compare",
                                "measurement_negative_control",
                                stream.effective,
                                "pr",
                            )
                    proof = json.loads((directory / PROOF_NAME).read_text().splitlines()[0])[
                        "proof"
                    ]
                    self.assertLess(
                        proof["prefix_end"], (directory / "native.timing").stat().st_size
                    )
                    with (
                        patch.object(
                            PrefixReader,
                            "read",
                            autospec=True,
                            side_effect=ValueError("missing frame"),
                        ),
                        self.assertRaises(ValueError),
                    ):
                        reader = PrefixReader(
                            directory / "native.timing", {"compare": binding}, "pr"
                        )
                        try:
                            reader.push(stream.histories["compare"][0])
                        finally:
                            reader.close()
                    records = (directory / PROOF_NAME).read_bytes()
                    changed = records.replace(b'"prefix_sha256":"', b'"prefix_sha256":"0', 1)
                    (directory / PROOF_NAME).write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, "proof differs"):
                        replay_runtime(directory, {"compare": binding}, "pr", stream.histories)

    def test_real_native_controls_and_removed_signals_reach_runtime_roles(self):
        for compiler in ("gcc", "clang"):
            for mode in (200, 201, 202, 203):
                with self.subTest(compiler=compiler, mode=mode):
                    _directory, _, stream = self.run_native(compiler, mode)
                    self.assertEqual(len(stream.effective), 24)
                    for name in CONTROL_CASES:
                        history = [r for r in stream.effective if r["case"] == name]
                        role = (
                            "measurement_negative_control"
                            if name == CONTROL_CASES[0]
                            else "measurement_positive_control"
                        )
                        bad = (
                            (mode == 201 and name == CONTROL_CASES[1])
                            or (mode == 202 and name == CONTROL_CASES[2])
                            or (mode == 203 and name == CONTROL_CASES[0])
                        )
                        if bad:
                            with self.assertRaises(ObservationError):
                                assess_case("legacy/" + name, role, history, "pr")
                        else:
                            assess_case("legacy/" + name, role, history, "pr")
                    self.assertEqual(stream.effective, stream.decisions)

    def test_current_prefix_corruption_future_isolation_and_storage_failure(self):  # noqa: PLR0912, PLR0915
        directory, binding, stream = self.run_native("gcc", 3)
        rows = stream.histories["compare"]
        raw = directory / "native.timing"
        original = raw.read_bytes()
        first = json.loads((directory / PROOF_NAME).read_text().splitlines()[0])["proof"]
        # Only the current prefix is required and read. No later frame or EOF wait.
        raw.write_bytes(original[: first["prefix_end"]])
        reader = PrefixReader(raw, {"compare": binding}, "pr")
        try:
            self.assertEqual(reader.push(rows[0]), first)
        finally:
            reader.close()
        for mutation in (
            original[: first["prefix_end"] - 1],
            original[:200] + b"x" + original[201:],
            original[:524764] + b"\x02" + original[524765:],
        ):
            raw.write_bytes(mutation)
            reader = PrefixReader(raw, {"compare": binding}, "pr")
            try:
                with self.assertRaises(ValueError):
                    reader.push(rows[0])
            finally:
                reader.close()
        raw.write_bytes(original)
        for change in ("pilot", "class_count"):
            row = copy.deepcopy(rows[0])
            if change == "pilot":
                row["pilot"]["center"] += 1
            else:
                row["input_audit"]["class_count"][0] += 1
                row["input_audit"]["class_count"][1] -= 1
            reader = PrefixReader(raw, {"compare": binding}, "pr")
            try:
                with self.assertRaises(ValueError):
                    reader.push(row)
            finally:
                reader.close()
        old = {**binding, "numerical_sha256": "0" * 64}
        with self.assertRaises(ValueError):
            PrefixReader(raw, {"compare": old}, "pr")
        with self.assertRaises(ValueError):
            PrefixReader(raw, {"compare": binding}, "periodic")

        class FullDisk(io.BytesIO):
            def write(self, data):
                message = "fixture disk full"
                raise OSError(message)

        with (directory / "storage-fault.stderr").open("wb") as errors:
            worker = Worker(raw, {"compare": binding}, errors)
            try:
                self.assertEqual(
                    resource.prlimit(worker.process.pid, resource.RLIMIT_AS),
                    (256 * 1024**2, 256 * 1024**2),
                )
                broken = RuntimeStream(("compare",), "pr", bindings={"compare": binding})
                broken.attach(worker, FullDisk())
                broken.deadline = time.monotonic() + 10
                ack = io.BytesIO()
                with self.assertRaises(OSError):
                    broken.consume(canonical(rows[0]) + b"\n", ack)
                self.assertEqual(ack.getvalue(), b"")
                self.assertEqual(len(broken.decisions), 1)
            finally:
                worker.close()
        raw.write_bytes(original + b"x")
        reader = PrefixReader(raw, {"compare": binding}, "pr")
        try:
            for row in rows:
                reader.push(row)
            with self.assertRaisesRegex(ValueError, "Trailing"):
                reader.finish()
        finally:
            reader.close()

    def test_maximum_pr_support_fits_bounded_worker(self):
        directory, _binding, stream = self.run_native("gcc", 100)
        self.assertEqual(len(stream.effective), 8)
        self.assertEqual(stream.effective[-1]["candidate_statistical_outcome"], "inconclusive")
        receipts = [json.loads(line) for line in (directory / PROOF_NAME).read_text().splitlines()]
        self.assertLess(max(r["runtime"]["seconds"] for r in receipts), 10)
        self.assertTrue(
            all(r["runtime"]["address_space_ceiling"] == 256 * 1024**2 for r in receipts)
        )

    def test_no_ack_after_final_processing_exceeds_deadline(self):
        stream = ObservationStream(("compare",), "pr")
        stream.deadline = time.monotonic() + 0.01

        def slow(line):
            time.sleep(0.02)

        stream.observe = slow
        ack = io.BytesIO()
        with self.assertRaisesRegex(ValueError, "before ACK"):
            stream.consume(b"{}\n", ack)
        self.assertEqual(ack.getvalue(), b"")

    def test_worker_stall_is_bounded(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            start_new_session=True,
        )
        worker = Worker.__new__(Worker)
        worker.process = process
        worker.buffer = b""
        try:
            with self.assertRaisesRegex(ValueError, "deadline"):
                worker.exchange({"finish": True}, time.monotonic() + 0.05)
        finally:
            worker.close()


if __name__ == "__main__":
    unittest.main()
