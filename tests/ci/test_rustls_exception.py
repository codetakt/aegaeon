"""Exercise refusal boundaries of the one-off security CI admission."""

# stdlib unittest runs before the Nix toolchain is installed.
# ruff: noqa: PT009, PT027

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "rustls_exception", Path(__file__).parents[2] / "scripts/ci/rustls_exception.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def context():
    source = "a" * 40
    pr = {
        "number": 228,
        "state": "open",
        "draft": False,
        "base": {"ref": "main", "sha": MODULE.BASE},
        "head": {"repo": {"full_name": MODULE.REPOSITORY}, "ref": MODULE.BRANCH, "sha": source},
        "title": "fix(deps): update rustls [skip ci]",
    }
    return {
        "repository": MODULE.REPOSITORY,
        "actual_base": MODULE.BASE,
        "pr": pr,
        "event_name": "pull_request",
        "event": {"number": 228, "pull_request": copy.deepcopy(pr)},
        "source_head": source,
        "source_descends_product": True,
        "source_parents_linear": True,
        "changed_paths": sorted(MODULE.CI_PATHS),
        "regular_file_modes": True,
        "test_sha": "b" * 40,
        "test_tree": "c" * 40,
        "source_tree": "c" * 40,
        "test_message": "Merge #228 [skip ci]",
        "signatures": [
            {"sha": MODULE.PRODUCT, "verified": True, "reason": "valid"},
            {"sha": source, "verified": True, "reason": "valid"},
        ],
    }


class ExceptionTests(unittest.TestCase):
    def test_normal_workflow_retains_protected_aggregate(self):
        root = Path(__file__).parents[2]
        workflow = (root / ".github/workflows/pr.yml").read_text()
        code = textwrap.dedent(
            workflow.split("PR_NEEDS_JSON=$(python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
        )
        needs = {name: {"result": "success"} for name in MODULE.REGULAR_JOBS}
        needs["plan"]["outputs"] = {"scope": "full"}
        needs.update({"exception": {"result": "success"}, "security_patch": {"result": "skipped"}})
        for failing in (None, *sorted(MODULE.REGULAR_JOBS), "exception", "security_patch"):
            broken = copy.deepcopy(needs)
            if failing is not None:
                broken[failing]["result"] = "failure"
            env = {**os.environ, "PR_NEEDS_JSON": json.dumps(broken)}
            route = subprocess.run(  # noqa: S603 - execute the checked-in workflow snippet
                [sys.executable, "-c", code], env=env, capture_output=True, check=False
            )
            if route.returncode:
                self.assertIn(failing, {"exception", "security_patch"})
                continue
            env["PR_NEEDS_JSON"] = route.stdout.decode()
            result = subprocess.run(  # noqa: S603 - fixed repository checker
                [
                    sys.executable,
                    str(root / "scripts/ci/check_pr_results.py"),
                    "--policy",
                    str(root / "ci/pr-policy.json"),
                ],
                env=env,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode == 0, failing is None)

    def test_only_scoped_events_select_exception(self):
        self.assertTrue(MODULE.selects_exception("pull_request", {"number": 228}))
        self.assertFalse(MODULE.selects_exception("pull_request", {"number": 226}))
        for number, expected in ((228, True), (229, False)):
            event = {
                "merge_group": {"head_ref": f"refs/heads/gh-readonly-queue/main/pr-{number}-abcdef"}
            }
            self.assertEqual(MODULE.selects_exception("merge_group", event), expected)
        with self.assertRaises(ValueError):
            MODULE.selects_exception("workflow_dispatch", {})

    def test_valid_pr_and_merge_group(self):
        data = context()
        MODULE.validate_context(data)
        data["event_name"] = "merge_group"
        data["event"] = {
            "merge_group": {
                "base_sha": MODULE.BASE,
                "base_ref": "refs/heads/main",
                "head_sha": data["test_sha"],
            }
        }
        MODULE.validate_context(data)
        for key, value in (
            ("base_sha", "d" * 40),
            ("head_sha", "d" * 40),
            ("base_ref", "refs/heads/other"),
        ):
            broken = copy.deepcopy(data)
            broken["event"]["merge_group"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.validate_context(broken)
        data["test_message"] = "Merge without skip marker"
        with self.assertRaises(ValueError):
            MODULE.validate_context(data)

    def test_source_and_scope_refusals(self):
        changes = {
            "repository": "other/repo",
            "actual_base": "d" * 40,
            "source_head": "d" * 40,
            "source_descends_product": False,
            "source_parents_linear": False,
            "regular_file_modes": False,
            "test_tree": "d" * 40,
            "signatures": [],
            "changed_paths": sorted(MODULE.CI_PATHS | {"c/dudect.h"}),
        }
        for key, value in changes.items():
            data = context()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.validate_context(data)

    def test_pr_identity_and_configuration_refusals(self):
        for field, value in (
            ("draft", True),
            ("number", 229),
            ("state", "closed"),
            ("title", "no skip"),
        ):
            data = context()
            data["pr"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                MODULE.validate_context(data)
        for target, key, value in (
            ("base", "sha", "d" * 40),
            ("base", "ref", "other"),
            ("head", "ref", "other"),
            ("head", "repo", {"full_name": "other/repo"}),
        ):
            data = context()
            data["pr"][target][key] = value
            with self.subTest(target=target, key=key), self.assertRaises(ValueError):
                MODULE.validate_context(data)
        data = context()
        data["signatures"][-1]["verified"] = False
        with self.assertRaises(ValueError):
            MODULE.validate_context(data)

    def test_stale_event_is_rejected(self):
        for key in ("base", "head"):
            data = context()
            data["event"]["pull_request"][key]["sha"] = "d" * 40
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.validate_context(data)

    def test_required_inventory_and_failures(self):
        needs = {name: {"result": "skipped"} for name in MODULE.REGULAR_JOBS}
        needs.update(
            {
                "exception": {"result": "success", "outputs": {"admitted": "true"}},
                "security_patch": {"result": "success"},
            }
        )
        MODULE.validate_results(needs)
        for name in needs:
            for result in ("failure", "cancelled", "missing"):
                broken = copy.deepcopy(needs)
                if result == "missing":
                    del broken[name]
                else:
                    broken[name]["result"] = result
                with self.subTest(name=name, result=result), self.assertRaises(ValueError):
                    MODULE.validate_results(broken)
        for name in MODULE.REGULAR_JOBS:
            broken = copy.deepcopy(needs)
            broken[name]["result"] = "success"
            with self.subTest(unexpected_lane=name), self.assertRaises(ValueError):
                MODULE.validate_results(broken)
        needs["security_patch"]["result"] = "skipped"
        with self.assertRaises(ValueError):
            MODULE.validate_results(needs)


if __name__ == "__main__":
    unittest.main()
