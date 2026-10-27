"""Required Cargo invocations must execute tests, not merely accept a filter."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/validation/run_required_cargo_test.sh"


class RequiredCargoExecutionTests(unittest.TestCase):
    def run_fixture(self, output, status=0, *, tee_status=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cargo = directory / "cargo"
            cargo.write_text(
                f"#!{sys.executable}\nimport sys\n"
                f"assert sys.argv[1:] == ['test', '-p', 'fixture', 'selected', '--', '--exact']\n"
                f"print({output!r})\nraise SystemExit({status})\n"
            )
            cargo.chmod(0o755)
            if tee_status is not None:
                tee = directory / "tee"
                tee.write_text(
                    f"#!{sys.executable}\nimport sys\nsys.stdin.read()\n"
                    f"raise SystemExit({tee_status})\n"
                )
                tee.chmod(0o755)
            environment = {**os.environ, "PATH": f"{directory}:{os.environ['PATH']}"}
            for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
                environment.pop(key, None)
            bash = shutil.which("bash")
            assert bash
            return subprocess.run(  # noqa: S603 - fixed helper and owned temporary Cargo fixture
                [bash, str(SCRIPT), "-p", "fixture", "selected", "--", "--exact"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

    def test_empty_missing_and_ignored_only_results_are_rejected(self):
        for output in (
            "",
            "running 1 test\ntest selected ... ok",
            "test result: ok. 0 passed; 0 failed; 0 ignored;",
            "test result: ok. 0 passed; 0 failed; 1 ignored;",
        ):
            with self.subTest(output=output):
                assert self.run_fixture(output).returncode != 0

    def test_passing_execution_with_other_empty_targets_is_retained(self):
        output = (
            "test result: ok. 0 passed; 0 failed; 0 ignored;\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
            "test result: ok. 0 passed; 0 failed; 0 ignored;"
        )
        result = self.run_fixture(output)
        assert result.returncode == 0, result.stderr
        assert result.stdout.rstrip() == output

    def test_cargo_failure_is_preserved_even_after_successful_summary(self):
        result = self.run_fixture("test result: ok. 1 passed; 0 failed; 0 ignored;", 37)
        assert result.returncode == 37

    def test_capture_failure_is_preserved(self):
        result = self.run_fixture("test result: ok. 1 passed; 0 failed; 0 ignored;", tee_status=41)
        assert result.returncode == 41

    def test_failed_target_cannot_be_hidden_by_other_success(self):
        result = self.run_fixture(
            "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
            "test result: FAILED. 0 passed; 1 failed; 0 ignored;"
        )
        assert result.returncode != 0

    def test_utf8_parity_selection_has_a_current_integration_test(self):
        workflow = (ROOT / ".github/workflows/verification.yml").read_text()
        source = (ROOT / "crates/jose/tests/json_header_parity.rs").read_text()
        assert "--test json_header_parity -- tlv_utf8_values_match_json_header" in workflow
        assert "fn tlv_utf8_values_match_json_header(" in source

    def test_workflow_selects_current_duplicate_rejection_tests(self):
        text = (ROOT / ".github/workflows/verification.yml").read_text()
        assert "parse_client_registration_value_rejects_duplicate_keys" not in text
        assert "test_extract_nonce_from_proof_rejects_duplicate_keys" not in text
        for name, source in (
            (
                "parse_client_registration_rejects_duplicate_keys",
                "dcr/tests/client_registration.rs",
            ),
            ("test_dpop_duplicate_nonce_claims_are_invalid", "middleware/dpop/tests.rs"),
        ):
            assert text.count(name) == 2
            assert f"fn {name}(" in (ROOT / "crates/server/src" / source).read_text()
        assert text.count("bash scripts/validation/run_required_cargo_test.sh") == 3


if __name__ == "__main__":
    unittest.main()
