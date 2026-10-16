"""Fixed opportunity inventory, irreversible failure accounting and identities."""

# ruff: noqa: E402, PT009, PT027 -- unittest repository fixtures
from __future__ import annotations

import copy
import sys
import unittest
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import dudect_hosted_campaign as campaign
import prepare_dudect_hosted as prepare


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.spec = campaign.specification()
        self.env = {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_RUN_ID": "123",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/" + self.spec["branch_prefix"] + "01",
        }

    def test_exact_design_is_minimum_and_inventories_partition_299(self):
        self.assertLess(Fraction(99, 100) ** 299, Fraction(1, 20))
        self.assertGreater(Fraction(99, 100) ** 298, Fraction(1, 20))
        self.assertEqual(
            [s for b in range(1, 20) for s in campaign.slots(self.spec, b)], list(range(1, 300))
        )
        self.assertEqual(len(campaign.slots(self.spec, 19)), 11)
        for batch in (0, 20, True, 1.5):
            with self.assertRaises(ValueError):
                campaign.slots(self.spec, batch)

    def test_replacement_unknown_ref_or_wrong_batch_slot_is_rejected(self):
        for key, value in (
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("GITHUB_SHA", "unknown"),
            ("GITHUB_RUN_ID", ""),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_REF", "refs/heads/" + self.spec["branch_prefix"] + "20"),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                campaign.invocation(self.spec, {**self.env, key: value}, 1)
        with self.assertRaises(ValueError):
            campaign.invocation(self.spec, self.env, 17)

    def test_slot_identity_is_frozen_before_build(self):
        with patch.dict(campaign.os.environ, self.env, clear=True):
            a, b = campaign.context(1), campaign.context(2)
        self.assertNotEqual(a["slot"], b["slot"])
        self.assertEqual(a["spec_sha256"], b["spec_sha256"])
        self.assertFalse(a["prior_screen_included"])
        self.assertEqual(a["batch_slots"], list(range(1, 17)))

    def test_package_change_rejected(self):
        original = self.spec["packages"]
        campaign.check_packages(original)
        for key in original:
            altered = copy.deepcopy(original)
            altered[key] = {}
            with self.assertRaises(ValueError):
                campaign.check_packages(altered)

    def test_only_all_299_successes_satisfy_zero_failure_criterion(self):
        rows = [
            {"slot": n, "passed": True, "attempt": 1, "revision": "a" * 40} for n in range(1, 300)
        ]
        incomplete = campaign.assess_ledger(self.spec, rows[:-1])
        self.assertFalse(incomplete["zero_failure_criterion_met"])
        self.assertIsNone(incomplete["conditional_one_sided_upper_bound"])
        complete = campaign.assess_ledger(self.spec, rows)
        self.assertTrue(complete["zero_failure_criterion_met"])
        self.assertLess(complete["conditional_one_sided_upper_bound"], 0.01)
        self.assertFalse(complete["ci_admission"])

    def test_failed_or_unrecoverable_opportunity_stops_new_batches_without_ci_claim(self):
        rows = [
            {
                "slot": 1,
                "passed": False,
                "attempt": 1,
                "revision": "a" * 40,
                "reason": "archive_missing",
            }
        ]
        result = campaign.assess_ledger(self.spec, rows)
        self.assertTrue(result["stop_new_batches"])
        self.assertEqual(result["failures"], [1])
        self.assertIsNone(result["conditional_one_sided_upper_bound"])
        self.assertFalse(result["zero_failure_criterion_met"])

    def test_duplicate_replacement_and_candidate_mix_rejected(self):
        row = {"slot": 1, "passed": True, "attempt": 1, "revision": "a" * 40}
        for rows in (
            [row, row],
            [{**row, "attempt": 2}],
            [{**row, "slot": 300}],
            [row, {**row, "slot": 2, "revision": "b" * 40}],
            [{**row, "passed": 1}],
        ):
            with self.assertRaises(ValueError):
                campaign.assess_ledger(self.spec, rows)

    def test_preparer_rejects_bad_slot_before_allocating_or_building(self):
        with (
            patch.dict(campaign.os.environ, self.env, clear=True),
            patch.object(prepare.hosted, "freeze") as freeze,
            self.assertRaises(ValueError),
        ):
            prepare.prepare(Path("unused"), 17)
        freeze.assert_not_called()

    def test_workflow_is_branch_scoped_and_preserves_failed_jobs(self):
        text = (ROOT / ".github/workflows/dudect-hosted-reliability.yml").read_text()
        self.assertIn("branches: ['ci/dudect-hosted-reliability-20261017-b*']", text)
        self.assertIn("fail-fast: false", text)
        self.assertIn("max-parallel: 16", text)
        self.assertIn("timeout-minutes: 152", text)
        self.assertIn("if: ${{ always() }}", text)
        self.assertNotIn("workflow_dispatch:", text)
        self.assertNotIn("continue-on-error", text)


if __name__ == "__main__":
    unittest.main()
