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
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
"""
NEGATIVE = """Check 1: wrong_size.assertion.1
 - Status: FAILURE
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


if __name__ == "__main__":
    unittest.main()
