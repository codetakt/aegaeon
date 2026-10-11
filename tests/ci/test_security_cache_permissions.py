# ruff: noqa: PT009, PT027 - unittest discovery; assertions also run under Python -O
"""Check the security cache's job grant and reusable caller permission ceiling."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_PERMISSIONS = {"contents": "read", "id-token": "write"}
PERMISSION_RANKS = {"none": 0, "read": 1, "write": 2}


class SecurityCachePermissionsTests(unittest.TestCase):
    def setUp(self):
        self.security = yaml.safe_load((ROOT / ".github/workflows/security.yml").read_text())
        self.caller = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())

    def check_permissions(self, security, caller):
        self.assertEqual(
            security["jobs"]["security-stage"].get("permissions", {}), REQUIRED_PERMISSIONS
        )
        job = caller["jobs"]["security"]
        self.assertEqual(job["uses"], "./.github/workflows/security.yml")
        ceiling = job.get("permissions", caller.get("permissions", {}))
        for permission, level in REQUIRED_PERMISSIONS.items():
            self.assertGreaterEqual(
                PERMISSION_RANKS[ceiling.get(permission, "none")], PERMISSION_RANKS[level]
            )

    def test_cache_job_grant_and_reusable_caller_ceiling(self):
        self.check_permissions(self.security, self.caller)
        # Future unrelated security jobs do not inherit the token grant.
        self.assertEqual(self.security.get("permissions", {}).get("id-token", "none"), "none")
        steps = self.security["jobs"]["security-stage"]["steps"]
        setup = [step for step in steps if step.get("uses") == "./.github/actions/setup-nix-ci"]
        self.assertEqual(len(setup), 1)
        self.assertEqual(setup[0]["with"]["enable-flakehub-cache"], "true")

    def test_absent_or_incomplete_job_grant_is_rejected(self):
        for permission in (None, "contents", "id-token"):
            with self.subTest(removed=permission):
                security = copy.deepcopy(self.security)
                job = security["jobs"]["security-stage"]
                if permission is None:
                    job.pop("permissions")
                else:
                    job["permissions"].pop(permission)
                with self.assertRaises(self.failureException):
                    self.check_permissions(security, self.caller)

    def test_reusable_caller_cannot_drop_a_required_permission(self):
        for permission in REQUIRED_PERMISSIONS:
            with self.subTest(removed=permission):
                caller = copy.deepcopy(self.caller)
                caller["jobs"]["security"]["permissions"].pop(permission)
                with self.assertRaises(self.failureException):
                    self.check_permissions(self.security, caller)

    def test_job_grant_cannot_widen_token_or_repository_access(self):
        for permission, level in (("contents", "write"), ("actions", "write")):
            with self.subTest(permission=permission, level=level):
                security = copy.deepcopy(self.security)
                security["jobs"]["security-stage"]["permissions"][permission] = level
                with self.assertRaises(self.failureException):
                    self.check_permissions(security, self.caller)


if __name__ == "__main__":
    unittest.main()
