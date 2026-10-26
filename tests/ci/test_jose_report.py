"""Exercise JOSE workflow reporting without a second test invocation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class JoseReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        workflow = yaml.safe_load((ROOT / ".github/workflows/compliance.yml").read_text())
        self.job = workflow["jobs"]["rfc7520-vectors"]
        self.steps = {step.get("name"): step for step in self.job["steps"]}
        self.run_step = self.steps["Run RFC 7520 Test Vectors"]
        self.report_step = self.steps["Generate test report"]
        self.summary_step = next(
            step
            for step in workflow["jobs"]["conformance-summary"]["steps"]
            if step.get("name") == "Generate summary report"
        )
        nix = self.root / "nix"
        nix.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "with pathlib.Path('calls.jsonl').open('a') as out:\n"
            "    out.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1:2] == ['build']:\n"
            "    print('/owned/rfc-tests' if not os.environ.get('EMPTY_PACKAGE') else '')\n"
            "    sys.exit(int(os.environ.get('BUILD_EXIT', '0')))\n"
            "assert os.environ.get('AEGAEON_RFC_TEST_PACKAGE') == '/owned/rfc-tests'\n"
            "print('original JOSE stdout')\n"
            "print('original JOSE stderr', file=sys.stderr)\n"
            "sys.exit(int(os.environ.get('TEST_EXIT', '0')))\n"
        )
        nix.chmod(0o755)

    def execute(self, step: dict, **environment: str) -> subprocess.CompletedProcess[str]:
        bash = shutil.which("bash")
        assert bash is not None
        return subprocess.run(  # noqa: S603 - repository workflow and owned fixtures
            [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
            cwd=self.root,
            env={
                **os.environ,
                "PATH": f"{self.root}:{os.environ['PATH']}",
                "GITHUB_STEP_SUMMARY": str(self.root / "summary.md"),
                **environment,
            },
            text=True,
            capture_output=True,
            check=False,
        )

    def calls(self) -> list[list[str]]:
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def report(self, outcome: str) -> dict:
        result = self.execute(self.report_step, JOSE_TEST_OUTCOME=outcome)
        assert result.returncode == 0, result.stderr
        artifact = self.root / "rfc7520-test-results"
        artifact.mkdir(exist_ok=True)
        for name in ("rfc7520-results.json", "rfc7520.log"):
            source = self.root / name
            if source.is_file():
                shutil.copyfile(source, artifact / name)
        return json.loads((artifact / "rfc7520-results.json").read_text())

    def summary(self, outcome: str) -> str:
        (self.root / "summary.md").unlink(missing_ok=True)
        result = self.execute(self.summary_step, JOSE_JOB_RESULT=outcome)
        assert result.returncode == 0, result.stderr
        return next(
            line
            for line in (self.root / "summary.md").read_text().splitlines()
            if "RFC 7520 JOSE Vectors" in line
        )

    def test_original_command_runs_once_and_both_streams_are_retained(self) -> None:
        result = self.execute(self.run_step)
        assert result.returncode == 0, result.stderr
        expected = [
            "develop",
            ".#ci",
            "--command",
            "bash",
            "scripts/validation/run_required_cargo_test.sh",
            "--package",
            "aegaeon-jose",
            "--test",
            "rfc7520_vectors",
        ]
        assert self.calls() == [
            ["build", ".#rfc-tests", "--no-link", "--print-out-paths"],
            expected,
        ]
        log = (self.root / "rfc7520.log").read_bytes()
        assert b"original JOSE stdout" in log
        assert b"original JOSE stderr" in log
        report = self.report("success")
        assert report["log_sha256"] == hashlib.sha256(log).hexdigest()
        assert report["log_bytes"] == len(log)
        assert "✅ Pass" in self.summary("success")
        assert self.calls() == [
            ["build", ".#rfc-tests", "--no-link", "--print-out-paths"],
            expected,
        ]

    def test_test_failure_is_not_replaced_by_successful_reporting(self) -> None:
        result = self.execute(self.run_step, TEST_EXIT="17")
        assert result.returncode == 17
        assert self.report("failure")["test_step_outcome"] == "failure"
        assert "Failed or incomplete" in self.summary("failure")
        assert "Failed or incomplete" in self.summary("success")
        assert len(self.calls()) == 2

    def test_reporting_never_restarts_failed_cancelled_or_skipped_tests(self) -> None:
        (self.root / "rfc7520.log").write_text("partial output\n")
        for outcome in ("failure", "cancelled", "skipped", ""):
            with self.subTest(outcome=outcome):
                report = self.report(outcome)
                assert report["test_step_outcome"] == (outcome or "unavailable")
                assert "Failed or incomplete" in self.summary(outcome)
                assert not self.calls()

    def test_missing_or_empty_output_cannot_be_reported_as_pass(self) -> None:
        for content in (None, b""):
            with self.subTest(content=content):
                if content is not None:
                    (self.root / "rfc7520.log").write_bytes(content)
                self.report("success")
                assert "Failed or incomplete" in self.summary("success")
                assert not self.calls()

    def test_malformed_or_incompatible_report_cannot_be_reported_as_pass(self) -> None:
        assert self.execute(self.run_step).returncode == 0
        original = self.report("success")
        path = self.root / "rfc7520-test-results/rfc7520-results.json"
        for value in (
            "{",
            "null",
            "[]",
            "{}",
            '{"type":"suite","event":"ok"}',
            json.dumps({**original, "schema_version": 2}),
            json.dumps({**original, "suite": "other"}),
            json.dumps({**original, "log_bytes": 0}),
            json.dumps({**original, "log_sha256": "0" * 64}),
        ):
            with self.subTest(value=value):
                path.write_text(value)
                assert "Failed or incomplete" in self.summary("success")
        path.unlink()
        assert "Failed or incomplete" in self.summary("success")
        assert len(self.calls()) == 2

    def test_changed_retained_log_is_not_reported_as_pass(self) -> None:
        assert self.execute(self.run_step).returncode == 0
        self.report("success")
        (self.root / "rfc7520-test-results/rfc7520.log").write_text("truncated\n")
        assert "Failed or incomplete" in self.summary("success")

    def test_job_failure_dominates_a_successful_test_report(self) -> None:
        assert self.execute(self.run_step).returncode == 0
        self.report("success")
        for outcome in ("failure", "cancelled", "skipped", ""):
            with self.subTest(outcome=outcome):
                assert "Failed or incomplete" in self.summary(outcome)

    def test_log_write_failure_fails_the_required_step(self) -> None:
        (self.root / "rfc7520.log").mkdir()
        assert self.execute(self.run_step).returncode != 0
        assert len(self.calls()) == 2

    def test_workflow_retains_required_outcome_scope_and_uploads(self) -> None:
        assert "needs" not in self.job
        assert (
            self.job["if"]
            == "${{ github.event_name != 'pull_request' && github.event_name != 'merge_group' }}"
        )
        assert self.run_step["id"] == "jose-tests"
        assert "if" not in self.run_step
        assert not self.run_step.get("continue-on-error", False)
        assert self.report_step["if"] == "always()"
        assert self.report_step["env"]["JOSE_TEST_OUTCOME"] == "${{ steps.jose-tests.outcome }}"
        assert self.summary_step["env"]["JOSE_JOB_RESULT"] == "${{ needs.rfc7520-vectors.result }}"
        upload = self.steps["Upload test results"]
        assert upload["if"] == "always()"
        assert upload["with"]["if-no-files-found"] == "error"
        assert set(upload["with"]["path"].splitlines()) == {
            "rfc7520-results.json",
            "rfc7520.log",
        }

    def test_compile_failure_or_empty_package_prevents_test_execution(self) -> None:
        for environment in ({"BUILD_EXIT": "37"}, {"EMPTY_PACKAGE": "1"}):
            with self.subTest(environment=environment):
                (self.root / "calls.jsonl").unlink(missing_ok=True)
                result = self.execute(self.run_step, **environment)
                assert result.returncode != 0
                assert self.calls() == [["build", ".#rfc-tests", "--no-link", "--print-out-paths"]]

    def test_vectors_do_not_wait_for_an_unused_release_binary(self) -> None:
        assert "needs" not in self.job
        assert "continue-on-error" not in self.run_step
        assert self.job["if"] == (
            "${{ github.event_name != 'pull_request' && github.event_name != 'merge_group' }}"
        )
        assert not any("download-artifact@" in step.get("uses", "") for step in self.job["steps"])
