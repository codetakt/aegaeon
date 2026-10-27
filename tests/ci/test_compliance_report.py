"""Run workflow steps to preserve the required outcome without report-time retries."""

from __future__ import annotations

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


class ComplianceReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        job = yaml.safe_load((ROOT / ".github/workflows/compliance.yml").read_text())["jobs"][
            "rfc-must-requirements"
        ]
        self.steps = {step.get("name"): step for step in job["steps"]}
        self.run_step = self.steps["Run RFC compliance tests"]
        self.report_step = self.steps["Generate compliance report"]
        script = self.root / "scripts/validation/test_rfc_compliance.sh"
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/bash\nexit 0\n")
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
            "print('original stdout')\n"
            "print('original stderr', file=sys.stderr)\n"
            "sys.exit(int(os.environ.get('TEST_EXIT', '0')))\n"
        )
        nix.chmod(0o755)

    def execute(self, step: dict, **environment: str) -> subprocess.CompletedProcess[str]:
        bash = shutil.which("bash")
        assert bash is not None
        return subprocess.run(  # noqa: S603 - repository workflow and owned fixtures
            [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
            cwd=self.root,
            env={**os.environ, "PATH": f"{self.root}:{os.environ['PATH']}", **environment},
            text=True,
            capture_output=True,
            check=False,
        )

    def calls(self) -> list[list[str]]:
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_required_execution_runs_once_and_preserves_both_streams(self) -> None:
        result = self.execute(self.run_step)
        assert result.returncode == 0, result.stderr
        assert self.calls() == [
            ["build", ".#rfc-tests", "--no-link", "--print-out-paths"],
            ["develop", ".#ci", "--command", "./scripts/validation/test_rfc_compliance.sh"],
        ]
        log = (self.root / "rfc-compliance.log").read_text()
        assert "original stdout" in log
        assert "original stderr" in log
        result = self.execute(self.report_step, RFC_TEST_OUTCOME="success")
        assert result.returncode == 0, result.stderr
        assert len(self.calls()) == 2
        assert log in (self.root / "compliance-report.md").read_text()

    def test_failure_is_retained_despite_successful_report(self) -> None:
        result = self.execute(self.run_step, TEST_EXIT="17")
        assert result.returncode == 17
        report = self.execute(self.report_step, RFC_TEST_OUTCOME="failure")
        assert report.returncode == 0, report.stderr
        assert len(self.calls()) == 2
        content = (self.root / "compliance-report.md").read_text()
        assert "Test step outcome: failure" in content
        assert "original stderr" in content

    def test_reporting_does_not_restart_tests_for_any_outcome(self) -> None:
        (self.root / "rfc-compliance.log").write_text("retained partial output\n")
        for outcome in ("success", "failure", "cancelled", "skipped"):
            with self.subTest(outcome=outcome):
                result = self.execute(self.report_step, RFC_TEST_OUTCOME=outcome)
                assert result.returncode == 0, result.stderr
                assert not self.calls()
                report = (self.root / "compliance-report.md").read_text()
                assert f"Test step outcome: {outcome}" in report
                assert "retained partial output" in report

    def test_missing_log_and_outcome_are_explicit(self) -> None:
        result = self.execute(self.report_step, RFC_TEST_OUTCOME="")
        assert result.returncode == 0, result.stderr
        assert not self.calls()
        report = (self.root / "compliance-report.md").read_text()
        assert "Test step outcome: unavailable" in report
        assert "No test log was produced" in report

    def test_log_write_failure_fails_required_step(self) -> None:
        (self.root / "rfc-compliance.log").mkdir()
        result = self.execute(self.run_step)
        assert result.returncode != 0
        assert len(self.calls()) == 2

    def test_workflow_keeps_required_status_and_retains_report_and_log(self) -> None:
        assert self.run_step["id"] == "rfc-tests"
        assert "if" not in self.run_step
        assert not self.run_step.get("continue-on-error", False)
        assert self.report_step["if"] == "always()"
        assert self.report_step["env"]["RFC_TEST_OUTCOME"] == "${{ steps.rfc-tests.outcome }}"
        upload = self.steps["Upload compliance report"]
        assert upload["if"] == "always()"
        assert set(upload["with"]["path"].splitlines()) == {
            "compliance-report.md",
            "rfc-compliance.log",
        }

    def test_compile_failure_or_empty_package_stops_before_runtime(self) -> None:
        for environment in ({"BUILD_EXIT": "37"}, {"EMPTY_PACKAGE": "1"}):
            with self.subTest(environment=environment):
                calls = self.root / "calls.jsonl"
                calls.unlink(missing_ok=True)
                result = self.execute(self.run_step, **environment)
                assert result.returncode != 0
                assert self.calls() == [["build", ".#rfc-tests", "--no-link", "--print-out-paths"]]
