"""The package check must distinguish assertion controls from broken tools."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "kani_library_controls", ROOT / "nix/kani/check-libraries.py"
)
assert SPEC is not None
assert SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

FIXTURES = ROOT / "tests/fixtures/kani-library-controls"
POSITIVE = (FIXTURES / "sized_control.txt").read_text()
NEGATIVE = (FIXTURES / "wrong_size.txt").read_text()


class KaniLibraryControlsTests(unittest.TestCase):
    def _assert_source_integrity(self, *, replace_caller: bool, tamper_case: bool) -> None:
        approved = (ROOT / "nix/kani/library-controls.rs").read_bytes()
        altered = approved + b"\n// changed after approval\n"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "controls.rs"
            source.write_bytes(approved)
            output = Path(directory) / "results"
            observed = []

            def execute(
                command: list[str], case: Path, environment: dict[str, str]
            ) -> tuple[int, bool]:
                probe = Path(command[1])
                assert probe == case / "probe.rs"
                observed.append(probe.read_bytes())
                if len(observed) == 1:
                    if replace_caller:
                        source.write_bytes(altered)
                    if tamper_case:
                        probe.write_bytes(altered)
                (case / "output.log").write_text("accepted classifier result\n")
                return (1 if case.name == "wrong_size" else 0), False

            # Isolate source orchestration from verifier/log behavior. Even an
            # accepted classification must not admit a changed retained input.
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "check-libraries.py",
                        "--kani",
                        str(ROOT / "nix/kani/check-libraries.py"),
                        "--source",
                        str(source),
                        "--output",
                        str(output),
                    ],
                ),
                mock.patch.object(CHECKER, "execute", side_effect=execute) as execution,
                mock.patch.object(CHECKER, "classify", return_value=(True, [], 1)) as classifier,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                code = CHECKER.main()

            assert execution.call_count == classifier.call_count == 7
            assert observed == [approved] * 7
            assert source.read_bytes() == (altered if replace_caller else approved)
            record = json.loads((output / "RESULTS.json").read_text())
            assert code == (1 if tamper_case else 0)
            assert record["status"] == ("FAIL" if tamper_case else "PASS")
            assert record["source_sha256"] == CHECKER.CONTROL_SOURCE_SHA256
            assert record["approved_source_sha256"] == CHECKER.CONTROL_SOURCE_SHA256
            records = record["records"]
            assert [entry["status"] for entry in records] == (
                ["FAIL"] + ["PASS"] * 6 if tamper_case else ["PASS"] * 7
            )
            assert [entry["source_sha256"] for entry in records] == (
                [hashlib.sha256(altered if tamper_case else approved).hexdigest()]
                + [CHECKER.CONTROL_SOURCE_SHA256] * 6
            )

    def test_unchanged_case_copies_are_accepted(self) -> None:
        self._assert_source_integrity(replace_caller=False, tamper_case=False)

    def test_replacing_caller_source_keeps_approved_snapshot(self) -> None:
        self._assert_source_integrity(replace_caller=True, tamper_case=False)

    def test_tampered_retained_case_rejects_case_and_overall_result(self) -> None:
        self._assert_source_integrity(replace_caller=False, tamper_case=True)

    def test_unapproved_source_is_rejected_before_tool_execution(self) -> None:
        approved = (ROOT / "nix/kani/library-controls.rs").read_text()
        weakened = approved.replace(
            "assert!(std::mem::size_of_val(&value) == 1);",
            "assert!(std::mem::size_of_val(&value) >= 0);",
        )
        assert weakened != approved
        for contents in (weakened, "", None):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "controls.rs"
                if contents is not None:
                    source.write_text(contents)
                output = root / "results"
                # A missing executable would cause an error if Kani were invoked.
                result = subprocess.run(  # noqa: S603 - fixed Python/checker argv, no shell
                    [
                        sys.executable,
                        str(ROOT / "nix/kani/check-libraries.py"),
                        "--kani",
                        str(root / "must-not-be-invoked"),
                        "--source",
                        str(source),
                        "--output",
                        str(output),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert result.returncode == 1
                assert "Traceback" not in result.stderr
                record = json.loads((output / "RESULTS.json").read_text())
                assert record["status"] == "FAIL"
                assert record["error"] == (
                    "source_unreadable" if contents is None else "source_digest_mismatch"
                )
                assert record["records"] == []
                assert list(output.iterdir()) == [output / "RESULTS.json"]

    def test_completed_positive_and_assertion_control(self) -> None:
        assert CHECKER.classify(POSITIVE, "sized_control", 0, timed_out=False)[0]
        assert CHECKER.classify(NEGATIVE, "wrong_size", 1, timed_out=False)[0]

    def test_missing_completion_is_rejected(self) -> None:
        text = POSITIVE.split("Complete", maxsplit=1)[0]
        assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_unwind_failure_is_not_an_assertion_control(self) -> None:
        text = NEGATIVE.replace("wrong_size.assertion.1", "kani::intrinsic.unwind.0")
        assert not CHECKER.classify(text, "wrong_size", 1, timed_out=False)[0]

    def test_extra_failure_is_rejected(self) -> None:
        text = NEGATIVE + "Check 2: memory.safety_check.1\n - Status: FAILURE\n"
        assert not CHECKER.classify(text, "wrong_size", 1, timed_out=False)[0]

    def test_timeout_cannot_pass_with_successful_output(self) -> None:
        assert not CHECKER.classify(POSITIVE, "sized_control", 0, timed_out=True)[0]

    def test_vacuous_or_unknown_positive_is_rejected(self) -> None:
        for status in ("UNREACHABLE", "UNDETERMINED"):
            with self.subTest(status=status):
                text = POSITIVE.replace("Status: SUCCESS", f"Status: {status}", 1)
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_exit_status_must_agree(self) -> None:
        assert not CHECKER.classify(POSITIVE, "sized_control", 1, timed_out=False)[0]
        assert not CHECKER.classify(NEGATIVE, "wrong_size", 0, timed_out=False)[0]

    def test_tool_failure_after_assertion_output_is_rejected(self) -> None:
        for code in (101, 124, 137, -9, -15):
            with self.subTest(code=code):
                assert not CHECKER.classify(NEGATIVE, "wrong_size", code, timed_out=False)[0]

    def test_indented_or_malformed_property_header_is_rejected(self) -> None:
        for header in (" Check 2:", "\tCheck 2:", "Check\t2:", "Check broken:"):
            with self.subTest(header=header):
                text = POSITIVE + f"{header} callee.unwind.0\n - Status: FAILURE\n"
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_extra_or_indented_completion_marker_is_rejected(self) -> None:
        markers = (
            "VERIFICATION:- SUCCESSFUL\n",
            " VERIFICATION:- FAILED\n",
            "Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n",
            " Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n",
            " SUMMARY:\n ** 1 of 2 failed\n",
        )
        for marker in markers:
            with self.subTest(marker=marker):
                text = POSITIVE + marker
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_callee_checks_are_reconciled_with_property_summary(self) -> None:
        for status, suffix in (("SUCCESS", ""), ("UNREACHABLE", " (1 unreachable)")):
            with self.subTest(status=status):
                first, rest = POSITIVE.split("Check 2:", maxsplit=1)
                text = first + "Check 2:" + rest.replace("Status: SUCCESS", f"Status: {status}", 1)
                text = text.replace("0 of 4 failed", f"0 of 4 failed{suffix}")
                assert CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_property_summary_must_match_all_counts(self) -> None:
        for summary in ("1 of 4 failed", "0 of 5 failed", "0 of 4 failed (1 unreachable)"):
            with self.subTest(summary=summary):
                text = POSITIVE.replace("0 of 4 failed", summary)
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_unreported_properties_are_rejected(self) -> None:
        for status in ("SUCCESS", "UNREACHABLE", "not parsed"):
            with self.subTest(status=status):
                text = POSITIVE + f"Check 2: callee.unwind.0\n - Status: {status}\n"
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_duplicate_or_missing_property_identity_is_rejected(self) -> None:
        variants = (
            POSITIVE.replace("Check 1:", "Check 2:"),
            POSITIVE.replace("SUMMARY:", "Check 1: callee.unwind.0\n - Status: SUCCESS\nSUMMARY:"),
            POSITIVE.replace(
                "SUMMARY:", "Check 2: sized_control.assertion.1\n - Status: SUCCESS\nSUMMARY:"
            ),
        )
        for text in variants:
            with self.subTest(text=text):
                mismatched = text.replace("0 of 4 failed", "0 of 2 failed")
                assert not CHECKER.classify(mismatched, "sized_control", 0, timed_out=False)[0]

    def test_missing_or_duplicate_property_summary_is_rejected(self) -> None:
        for summary in ("", "SUMMARY:\n ** 0 of 4 failed\n" * 2):
            with self.subTest(summary=summary):
                text = POSITIVE.replace("SUMMARY:\n ** 0 of 4 failed\n", summary)
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_truncation_with_adjusted_summary_is_rejected(self) -> None:
        before = POSITIVE.split("Check 2:", maxsplit=1)[0]
        summary = POSITIVE.split("SUMMARY:", maxsplit=1)[1]
        text = (before + "SUMMARY:" + summary).replace("0 of 4 failed", "0 of 1 failed")
        assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_replaced_identity_with_unchanged_count_is_rejected(self) -> None:
        text = POSITIVE.replace(".safety_check.1", ".different_check.1")
        assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_orphan_property_content_is_rejected(self) -> None:
        for line in (
            "\t - Status: FAILURE\n",
            '\t - Description: "orphan"\n',
            "\t - Location: orphan.rs:1\n",
            "unknown property content\n",
        ):
            with self.subTest(line=line):
                text = POSITIVE.replace("\nSUMMARY:", "\n" + line + "\nSUMMARY:")
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_incomplete_property_body_is_rejected(self) -> None:
        line = next(line for line in POSITIVE.splitlines(keepends=True) if "- Description:" in line)
        text = POSITIVE.replace(line, "", 1)
        assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_unknown_case_and_duplicate_results_are_rejected(self) -> None:
        assert not CHECKER.classify(POSITIVE, "unknown", 0, timed_out=False)[0]
        text = "\nRESULTS:\n" + POSITIVE
        assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_orphan_status_outside_report_is_rejected(self) -> None:
        for text in (" - Status: FAILURE\n" + POSITIVE, POSITIVE + " - Status: FAILURE\n"):
            with self.subTest(text=text):
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]


if __name__ == "__main__":
    unittest.main()
