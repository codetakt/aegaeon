"""Fail-closed acceptance tests for the finite Kani evidence slice."""

# Keep this gate test executable with the standard library alone.
# ruff: noqa: PT009, PT027

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from run_kani_evidence import (
    accept_report,
    discover_metadata,
    evidence_line,
    log_tail,
    rejection_reason,
)

HARNESS = "module::proof_example"
REPORT = f"""Kani Rust Verifier 0.66.0 (cargo plugin)
Checking harness {HARNESS}...

RESULTS:
Check 1: {HARNESS}.assertion.1
\t - Status: SUCCESS
\t - Description: "expected value"
\t - Location: crates/ffi/src/kani_tests.rs:1:1 in function {HARNESS}

Check 2: function.unwind.0
\t - Status: SUCCESS
\t - Description: "unwinding assertion loop 0"


SUMMARY:
 ** 0 of 2 failed

VERIFICATION:- SUCCESSFUL
Verification Time: 0.123s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
"""


class AcceptanceTests(unittest.TestCase):
    def test_complete_property_result(self) -> None:
        self.assertEqual(len(accept_report(REPORT, HARNESS, 0)), 2)

    def test_exit_status_is_necessary(self) -> None:
        for code in (1, 101, 124, -9):
            with self.subTest(code=code), self.assertRaises(ValueError):
                accept_report(REPORT, HARNESS, code)

    def test_success_string_cannot_admit_missing_or_changed_evidence(self) -> None:
        mutations = [
            "VERIFICATION:- SUCCESSFUL\n",
            REPORT.replace(f"Checking harness {HARNESS}...", "Checking harness other..."),
            REPORT + "Checking harness other...\n",
            REPORT.replace("Check 2:", "Check 3:"),
            REPORT.replace("function.unwind.0", f"{HARNESS}.assertion.1"),
            REPORT.replace("Status: SUCCESS", "Status: FAILURE", 1),
            REPORT.replace("Status: SUCCESS", "Status: UNDETERMINED", 1),
            REPORT.replace("Status: SUCCESS", "Status: UNKNOWN", 1),
            REPORT.replace("Status: SUCCESS", "Status: UNREACHABLE", 1),
            REPORT.replace("0 of 2 failed", "0 of 3 failed"),
            REPORT.replace("1 total.", "0 total."),
            REPORT.split("\nSUMMARY:", maxsplit=1)[0],
            REPORT.replace("Check 2:", "unrecognized data\nCheck 2:"),
            REPORT.replace("RESULTS:", "RESULTS:\n\nRESULTS:"),
            REPORT.replace("Manual Harness Summary:", "Unsupported output:"),
        ]
        for index, report in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                accept_report(report, HARNESS, 0)

    def test_reviewed_unreachable_error_guard(self) -> None:
        guard = HARNESS + ".assertion.2"
        report = (
            REPORT.replace("function.unwind.0", guard)
            .replace(
                'Status: SUCCESS\n\t - Description: "unwinding assertion loop 0"',
                'Status: UNREACHABLE\n\t - Description: "unexpected success-path error"',
            )
            .replace("0 of 2 failed", "0 of 2 failed (1 unreachable)")
        )
        allowed = {guard: "unexpected success-path error"}
        self.assertEqual(len(accept_report(report, HARNESS, 0, allowed)), 2)
        with self.assertRaises(ValueError):
            accept_report(report, HARNESS, 0)
        with self.assertRaises(ValueError):
            accept_report(report, HARNESS, 0, {guard: "different error"})
        with self.assertRaises(ValueError):
            accept_report(REPORT, HARNESS, 0, allowed)

    def test_multiline_description(self) -> None:
        report = REPORT.replace('"expected value"', '"expected\n                        value"')
        self.assertEqual(len(accept_report(report, HARNESS, 0)), 2)

    def test_rejection_reason_names_budget_and_signal_causes(self) -> None:
        budget = ValueError("Kani exited with 124")
        self.assertEqual(
            rejection_reason(124, budget, 600),
            "wall-clock budget of 600s exceeded (timeout exit 124)",
        )
        signal = rejection_reason(-9, ValueError("Kani exited with -9"), 600)
        self.assertIn("signal 9", signal)
        parser = rejection_reason(1, ValueError("missing result summary"), 600)
        self.assertEqual(parser, "missing result summary")
        identity = rejection_reason(0, KeyError("proof_harnesses"), 600)
        self.assertEqual(identity, "'proof_harnesses'")

    def test_evidence_line_reports_exit_code_and_reason_without_bulk(self) -> None:
        result = {
            "harness": {"name": HARNESS, "file": "crates/ffi/src/kani_tests.rs"},
            "status": "rejected",
            "exit_code": 124,
            "wall_seconds": 600.02,
            "cpu_seconds": 41.5,
            "budget_seconds": 600,
            "log_sha256": "ab" * 32,
            "reason": rejection_reason(124, ValueError("Kani exited with 124"), 600),
            "properties": [{"id": f"{HARNESS}.assertion.{n}"} for n in range(1000)],
        }
        line = evidence_line(result)
        self.assertTrue(line.startswith("KANI-EVIDENCE "))
        self.assertNotIn("\n", line)
        parsed = json.loads(line.removeprefix("KANI-EVIDENCE "))
        self.assertEqual(parsed["harness"], HARNESS)
        self.assertEqual(parsed["status"], "rejected")
        self.assertEqual(parsed["exit_code"], 124)
        self.assertEqual(parsed["budget_seconds"], 600)
        self.assertIn("wall-clock budget", parsed["reason"])
        self.assertNotIn("properties", parsed)
        accepted = json.loads(
            evidence_line(
                {**result, "status": "accepted", "exit_code": 0, "reason": None}
            ).removeprefix("KANI-EVIDENCE ")
        )
        self.assertIsNone(accepted["reason"])

    def test_log_tail_is_bounded_and_tolerates_invalid_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "harness.log"
            path.write_text("".join(f"line {n}\n" for n in range(500)))
            tail = log_tail(path, max_lines=5, max_bytes=200)
            self.assertLessEqual(len(tail.splitlines()), 5)
            self.assertIn("line 499", tail)
            self.assertNotIn("line 400", tail)
            path.write_bytes(b"\xff\xfe before\nVERIFICATION:- FAILED\n")
            self.assertIn("VERIFICATION:- FAILED", log_tail(path))

    def test_compiled_identity_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory)
            harness = {"name": HARNESS, "file": "crates/ffi/src/kani_tests.rs"}
            proof = {
                "pretty_name": HARNESS,
                "original_file": harness["file"],
                "attributes": {"should_panic": False, "stubs": [], "verified_stubs": []},
            }
            data = {"crate_name": "ffi", "proof_harnesses": [proof]}
            with self.assertRaises(ValueError):
                discover_metadata(target, harness)
            path = target / "crate.kani-metadata.json"
            path.write_text(json.dumps(data))
            self.assertEqual(discover_metadata(target, harness)["proof"]["pretty_name"], HARNESS)
            duplicate = target / "other.kani-metadata.json"
            duplicate.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                discover_metadata(target, harness)
            duplicate.unlink()
            proof["original_file"] = "other.rs"
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                discover_metadata(target, harness)


if __name__ == "__main__":
    unittest.main()
