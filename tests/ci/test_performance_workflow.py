"""Direct scheduled performance caller prerequisite guards."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions must remain active under Python -O.
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PerformanceWorkflowTests(unittest.TestCase):
    def test_coverage_threshold_without_optional_host_tools(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        step = next(
            step
            for step in workflow["jobs"]["coverage"]["steps"]
            if step.get("name") == "Check coverage threshold"
        )
        script = step["run"].split("<<'EOF'\n", 1)[1].rsplit("\nEOF", 1)[0]
        bash, awk = shutil.which("bash"), shutil.which("awk")
        self.assertIsNotNone(bash)
        self.assertIsNotNone(awk)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            (tools / "awk").symlink_to(awk)
            environment = {**os.environ, "PATH": str(tools)}
            for hits, found, accepted in [
                (3999, 10000, False),
                (40, 100, True),
                (4001, 10000, True),
                (0, 0, False),
            ]:
                with self.subTest(hits=hits, found=found):
                    (root / "lcov.info").write_text(f"LF:{found}\nLH:{hits}\n")
                    result = subprocess.run(  # noqa: S603 - checked-in workflow and synthetic LCOV
                        [bash, "-c", script],
                        cwd=root,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode == 0, accepted, result.stdout + result.stderr
                    )
            (root / "lcov.info").unlink()
            result = subprocess.run(  # noqa: S603 - checked-in workflow with missing LCOV
                [bash, "-c", script],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, "missing LCOV must fail")

    def test_direct_http_policy_is_scoped_to_public_smoke(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        flags = {"AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY", "AEGAEON_REQUIRE_TLS_PROXY"}
        self.assertTrue(flags.isdisjoint(workflow.get("env", {})))
        for job in workflow["jobs"].values():
            self.assertTrue(flags.isdisjoint(job.get("env", {})))
            for step in job["steps"]:
                environment = step.get("env", {})
                if step.get("name") == "Run public smoke load test":
                    for flag in flags:
                        self.assertEqual(environment[flag], "0")
                    self.assertEqual(environment["PERF_SCENARIO"], "smoke")
                    self.assertEqual(environment["PERF_MANAGE_SERVER"], "1")
                    self.assertEqual(environment["AEGAEON_RUNTIME_ISSUER_HOST"], "127.0.0.1:18095")
                else:
                    self.assertTrue(flags.isdisjoint(environment))
        consumer = (ROOT / "crates/loadtest/src/scenarios/mod.rs").read_text()
        self.assertNotIn("X-Forwarded-Proto", consumer)
        self.assertNotIn('header("Forwarded"', consumer)

    def test_policy_mixed_execution_and_acceptance_share_pending_prerequisite(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        job = workflow["jobs"]["load-test"]
        self.assertEqual(workflow["env"]["POLICY_MIXED_PREREQUISITES"], "pending")
        for job_name, workflow_job in workflow["jobs"].items():
            with self.subTest(job=job_name):
                self.assertNotIn("POLICY_MIXED_PREREQUISITES", workflow_job.get("env", {}))
                for step in workflow_job["steps"]:
                    self.assertNotIn("POLICY_MIXED_PREREQUISITES", step.get("env", {}))
        steps = {step.get("name"): step for step in job["steps"]}
        kpi_steps = {step.get("name"): step for step in workflow["jobs"]["validate-kpis"]["steps"]}
        expected = "${{ env.POLICY_MIXED_PREREQUISITES == 'accepted' }}"
        for name, selected_steps in [
            ("Run policy-mixed load smoke", steps),
            ("Validate policy-mixed smoke SLOs", steps),
            ("Validate policy-mixed KPIs", kpi_steps),
        ]:
            with self.subTest(guard=name):
                self.assertEqual(selected_steps[name]["if"], expected)
        for name, selected_steps in [
            ("Report pending policy-mixed prerequisites", steps),
            ("Report pending policy-mixed KPI prerequisites", kpi_steps),
        ]:
            with self.subTest(notice=name):
                pending = selected_steps[name]
                self.assertEqual(
                    pending["if"],
                    "${{ always() && env.POLICY_MIXED_PREREQUISITES != 'accepted' }}",
                )
                for prerequisite in [
                    "activated HTTPS",
                    "client profile",
                    "public-login session",
                    "supplier",
                ]:
                    self.assertIn(prerequisite, pending["run"])
                self.assertIn("pending", pending["run"])
                self.assertIn("skipped", pending["run"])
                self.assertIn("$GITHUB_STEP_SUMMARY", pending["run"])
        self.assertIn(
            "validation and performance acceptance skipped",
            kpi_steps["Report pending policy-mixed KPI prerequisites"]["run"],
        )
        self.assertNotIn("AEG_LOADTEST_PROOF_ORIGIN", steps["Run policy-mixed load smoke"]["run"])
        self.assertNotIn("if", steps["Run public smoke load test"])
        self.assertNotIn("if", steps["Validate public smoke SLOs"])
        self.assertNotIn("if", kpi_steps["Validate public smoke KPIs"])
        self.assertIn("nix run .#perf-load", steps["Run public smoke load test"]["run"])


if __name__ == "__main__":
    unittest.main()
