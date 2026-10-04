"""Direct scheduled performance caller prerequisite guards."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions must remain active under Python -O.
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PerformanceWorkflowTests(unittest.TestCase):
    def test_policy_mixed_execution_and_acceptance_share_pending_prerequisite(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        job = workflow["jobs"]["load-test"]
        self.assertEqual(job["env"]["POLICY_MIXED_PREREQUISITES"], "pending")
        steps = {step.get("name"): step for step in job["steps"]}
        expected = "${{ env.POLICY_MIXED_PREREQUISITES == 'accepted' }}"
        for name in ["Run policy-mixed load smoke", "Validate policy-mixed smoke SLOs"]:
            self.assertEqual(steps[name]["if"], expected)
        pending = steps["Report pending policy-mixed prerequisites"]
        self.assertEqual(
            pending["if"], "${{ always() && env.POLICY_MIXED_PREREQUISITES != 'accepted' }}"
        )
        for prerequisite in [
            "activated HTTPS",
            "client profile",
            "public-login session",
            "supplier",
        ]:
            self.assertIn(prerequisite, pending["run"])
        self.assertIn("pending", pending["run"])
        self.assertNotIn("AEG_LOADTEST_PROOF_ORIGIN", steps["Run policy-mixed load smoke"]["run"])
        self.assertNotIn("if", steps["Run public smoke load test"])
        self.assertNotIn("if", steps["Validate public smoke SLOs"])
        self.assertIn("nix run .#perf-load", steps["Run public smoke load test"]["run"])


if __name__ == "__main__":
    unittest.main()
