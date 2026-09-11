"""The package check must distinguish assertion controls from broken tools."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "kani_library_controls", ROOT / "nix/kani/check-libraries.py"
)
assert SPEC is not None
assert SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

POSITIVE = """Check 1: sized_control.assertion.1
 - Status: SUCCESS
SUMMARY:
 ** 0 of 1 failed
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
"""
NEGATIVE = """Check 1: wrong_size.assertion.1
 - Status: FAILURE
SUMMARY:
 ** 1 of 1 failed
VERIFICATION:- FAILED
Complete - 0 successfully verified harnesses, 1 failures, 1 total.
"""


class KaniLibraryControlsTests(unittest.TestCase):
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
                text = POSITIVE.replace("Status: SUCCESS", f"Status: {status}")
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_exit_status_must_agree(self) -> None:
        assert not CHECKER.classify(POSITIVE, "sized_control", 1, timed_out=False)[0]
        assert not CHECKER.classify(NEGATIVE, "wrong_size", 0, timed_out=False)[0]

    def test_callee_checks_are_reconciled_with_property_summary(self) -> None:
        for status, suffix in (("SUCCESS", ""), ("UNREACHABLE", " (1 unreachable)")):
            with self.subTest(status=status):
                text = POSITIVE.replace(
                    "SUMMARY:", f"Check 2: callee.unwind.0\n - Status: {status}\nSUMMARY:"
                ).replace("0 of 1 failed", f"0 of 2 failed{suffix}")
                assert CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]

    def test_property_summary_must_match_all_counts(self) -> None:
        for summary in ("1 of 1 failed", "0 of 2 failed", "0 of 1 failed (1 unreachable)"):
            with self.subTest(summary=summary):
                text = POSITIVE.replace("0 of 1 failed", summary)
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
                mismatched = text.replace("0 of 1 failed", "0 of 2 failed")
                assert not CHECKER.classify(mismatched, "sized_control", 0, timed_out=False)[0]

    def test_missing_or_duplicate_property_summary_is_rejected(self) -> None:
        for summary in ("", "SUMMARY:\n ** 0 of 1 failed\n" * 2):
            with self.subTest(summary=summary):
                text = POSITIVE.replace("SUMMARY:\n ** 0 of 1 failed\n", summary)
                assert not CHECKER.classify(text, "sized_control", 0, timed_out=False)[0]


if __name__ == "__main__":
    unittest.main()
