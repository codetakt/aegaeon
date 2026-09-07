"""Regression tests for check selection, aggregate failures and local file links."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import pytest
import yaml
from check_doc_links import broken_links, local_links, snapshot
from check_pr_results import check_results
from pr_plan import build_plan, classify, path_scope

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "ci/pr-policy.json").read_text())


def change(path, old_mode="100644", new_mode="100644"):
    return {"path": path, "status": "M", "old_mode": old_mode, "new_mode": new_mode}


def results(scope):
    required = POLICY["scopes"][scope]
    return {
        "plan": {"result": "success", "outputs": {"scope": scope}},
        **{
            lane: {"result": "success" if lane in required else "skipped"}
            for lane in POLICY["scopes"]["full"]
        },
    }


class SelectionTests(unittest.TestCase):
    def test_scopes_and_conservative_fallbacks(self):
        cases = {
            "SECURITY.md": "docs",
            "docs/security/security-review/README.md": "docs",
            "docs/verification/claims/claim-definition.md": "integrity",
            "spec/server-assurance-contract.v1.json": "integrity",
            "spec/compliance-matrix.yaml": "integrity",
            "spec/unknown.json": "full",
            "scripts/validation/check_runtime_drift.py": "full",
            "docs/configurations/environment/new.md": "full",
            "README.md": "full",
            "docs/unknown.sh": "full",
            "docs/name\n.md": "full",
            "../docs/page.md": "full",
            "crates/server/src/main.rs": "full",
            "ci/pr-policy.json": "full",
            "scripts/ci/pr_plan.py": "full",
            ".github/workflows/pr.yml": "full",
            "flake.nix": "full",
            "flake.lock": "full",
            "nix/build-source.nix": "full",
        }
        for path, scope in cases.items():
            with self.subTest(path=path):
                assert classify([change(path)], POLICY)["scope"] == scope

    def test_mixed_and_empty_changes_select_full(self):
        assert classify([], POLICY)["scope"] == "full"
        assert classify([change("SECURITY.md"), change("unknown")], POLICY)["scope"] == "full"

    def test_special_modes_cannot_take_documentation_shortcut(self):
        for old, new in [
            ("100644", "100755"),
            ("120000", "120000"),
            ("000000", "160000"),
            ("100755", "100755"),
        ]:
            with self.subTest(old=old, new=new):
                assert classify([change("docs/a.md", old, new)], POLICY)["scope"] == "full"

    def test_runtime_document_literals_remain_classified(self):
        # Audit literal dependencies; computed paths still require review.
        for rust in (ROOT / "crates").rglob("*.rs"):
            for path in re.findall(r'"((?:docs/)[^"\n]+\.md)"', rust.read_text()):
                with self.subTest(rust=rust, path=path):
                    assert path_scope(path, POLICY)[0] == "full"

    def test_registered_evidence_documents_require_integrity(self):
        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, list):
                for child in value:
                    yield from strings(child)
            elif isinstance(value, dict):
                for child in value.values():
                    yield from strings(child)

        records = [
            *(ROOT / "spec").glob("*.json"),
            *(ROOT / "docs/releases/evidence").glob("*.json"),
        ]
        for record in records:
            for path in strings(json.loads(record.read_text())):
                if path.startswith("docs/") and path.endswith(".md") and (ROOT / path).is_file():
                    with self.subTest(record=record, path=path):
                        assert path_scope(path, POLICY)[0] in {"integrity", "full"}


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))

    def test_valid_scopes(self):
        for scope in POLICY["scopes"]:
            check_results(results(scope), POLICY)

    def test_selected_failure_skip_cancel_or_missing_result_rejected(self):
        for lane in POLICY["scopes"]["full"]:
            for result in ("failure", "skipped", "cancelled", None):
                needs = results("full")
                needs[lane]["result"] = result
                with (
                    self.subTest(lane=lane, result=result),
                    pytest.raises(ValueError, match=rf"^{lane}:"),
                ):
                    check_results(needs, POLICY)

    def test_failed_unselected_job_is_rejected(self):
        needs = results("docs")
        needs["security"]["result"] = "failure"
        with pytest.raises(ValueError, match="security: failure"):
            check_results(needs, POLICY)

    def test_planning_failure_unknown_scope_and_incomplete_inventory_rejected(self):
        mutations = []
        for result in ("failure", "skipped", "cancelled"):
            needs = results("docs")
            needs["plan"]["result"] = result
            mutations.append(needs)
        needs = results("docs")
        needs["plan"]["outputs"]["scope"] = "unknown"
        mutations.append(needs)
        needs = results("docs")
        del needs["core"]
        mutations.append(needs)
        needs = results("docs")
        needs["unexpected"] = {"result": "success"}
        mutations.append(needs)
        for needs in mutations:
            with pytest.raises(ValueError, match=r"classification|check inventory"):
                check_results(needs, POLICY)


class GitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "core.excludesFile", "/dev/null")
        self.git("config", "core.hooksPath", "/dev/null")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.write("SECURITY.md", "[existing debt](absent.md)\n")
        self.write("implementation.rs", "fn main() {}\n")
        self.base = self.commit()

    def git(self, *args):
        # Fixed executable and fixture argv; no shell evaluation.
        return (
            subprocess.check_output(  # noqa: S603
                ["git", "-C", str(self.repo), *args]  # noqa: S607 - Git from the pinned shell
            )
            .decode()
            .strip()
        )

    def write(self, path, text):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self):
        self.git("add", "--force", ".")
        # Synthetic fixtures have no signing identity; real repository commits are signed.
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "test: fixture")
        return self.git("rev-parse", "HEAD")

    def test_unavailable_revision_cli_selects_full_and_records_reason(self):
        output = self.repo / "plan.json"
        github_output = self.repo / "github-output"
        subprocess.run(  # noqa: S603 - fixed Python executable and fixture argv
            [
                sys.executable,
                str(ROOT / "scripts/ci/pr_plan.py"),
                "--repo",
                str(self.repo),
                "--base",
                "0" * 40,
                "--head",
                self.base,
                "--policy",
                str(ROOT / "ci/pr-policy.json"),
                "--output",
                str(output),
            ],
            env={**os.environ, "GITHUB_OUTPUT": str(github_output)},
            check=True,
            stdout=subprocess.DEVNULL,
        )
        plan = json.loads(output.read_text())
        assert plan["scope"] == "full"
        assert "fallback" in plan
        assert len(plan["classifier_sha256"]) == 64
        assert github_output.read_text() == "scope=full\n"

    def test_renamed_code_to_markdown_keeps_deleted_code_in_diff(self):
        (self.repo / "docs").mkdir()
        self.git("mv", "implementation.rs", "docs/prose.md")
        plan = build_plan(self.repo, self.base, self.commit(), POLICY)
        assert plan["scope"] == "full"
        assert {r["path"] for r in plan["changes"]} == {"implementation.rs", "docs/prose.md"}

    def test_large_diff_does_not_truncate_late_implementation_file(self):
        for index in range(350):
            self.write(f"docs/{index:03}.md", "Text\n")
        self.write("zzz.rs", "fn main() {}\n")
        plan = build_plan(self.repo, self.base, self.commit(), POLICY)
        assert len(plan["changes"]) == 351
        assert plan["scope"] == "full"

    def test_deleted_and_spaced_document_names(self):
        self.git("rm", "SECURITY.md")
        self.write("docs/with spaces.md", "Text\n")
        plan = build_plan(self.repo, self.base, self.commit(), POLICY)
        assert plan["scope"] == "docs"
        assert len(plan["changes"]) == 2

    def test_head_diff_does_not_include_unrelated_base_changes(self):
        self.write("SECURITY.md", "Changed prose\n")
        head = self.commit()
        self.git("checkout", "-q", "--detach", self.base)
        self.write("other.rs", "fn main() {}\n")
        updated_base = self.commit()
        assert build_plan(self.repo, updated_base, head, POLICY)["scope"] == "docs"

    def test_link_baseline_and_removed_target(self):
        self.write("docs/page.md", "[source](../implementation.rs)\n")
        base = self.commit()
        self.git("rm", "implementation.rs")
        head = self.commit()
        previous = Path.cwd()
        os.chdir(self.repo)
        try:
            new = broken_links(*snapshot(head)) - broken_links(*snapshot(base))
        finally:
            os.chdir(previous)
        assert new == {("docs/page.md", "../implementation.rs")}

    def test_snapshot_without_markdown(self):
        self.git("rm", "SECURITY.md")
        head = self.commit()
        previous = Path.cwd()
        os.chdir(self.repo)
        try:
            assert snapshot(head) == ({}, {"implementation.rs"})
        finally:
            os.chdir(previous)


class LinkTests(unittest.TestCase):
    def test_local_destinations_and_examples(self):
        text = """[a](file.md#anchor) ![image](images/a.png)
[b](<with spaces.md>) [c](encoded%20space.md)
[reference]: ../README.md "Title"
[remote](https://example.invalid/a) [anchor](#heading)
`[example](missing.md)`
```md
[example](missing.md)
```
"""
        assert local_links(text) == {
            "file.md",
            "images/a.png",
            "with spaces.md",
            "encoded space.md",
            "../README.md",
        }

    def test_directories_and_missing_targets(self):
        assert broken_links(
            {"docs/a.md": "[d](../images) [x](missing.md)"}, {"docs/a.md", "images/a.png"}
        ) == {("docs/a.md", "missing.md")}


class WiringTests(unittest.TestCase):
    def test_reusable_permissions_cover_even_skipped_nested_jobs(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        ranks = {"none": 0, "read": 1, "write": 2}
        for lane, job in workflow["jobs"].items():
            if "uses" not in job:
                continue
            child = yaml.safe_load((ROOT / job["uses"]).read_text())
            caller_permissions = job.get("permissions", workflow["permissions"])
            for child_id, nested in child["jobs"].items():
                for permission, level in nested.get(
                    "permissions", child.get("permissions", {})
                ).items():
                    with self.subTest(lane=lane, child=child_id, permission=permission):
                        assert ranks[caller_permissions.get(permission, "none")] >= ranks[level]
        compliance = yaml.safe_load((ROOT / ".github/workflows/compliance.yml").read_text())
        assert compliance["permissions"] == {"contents": "read"}
        for job in compliance["jobs"].values():
            assert "permissions" in job
        assert compliance["jobs"]["rfc-must-requirements"]["permissions"] == {
            "contents": "read",
            "id-token": "write",
        }

    def test_workflow_selection_and_dependencies_match_policy(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        events = workflow.get("on", workflow.get(True))
        assert events["pull_request"]["types"] == ["opened", "synchronize", "reopened"]
        jobs = workflow["jobs"]
        assert set(jobs["required"]["needs"]) == set(POLICY["scopes"]["full"]) | {"plan"}
        assert "always()" in jobs["required"]["if"]
        assert (
            jobs["required"]["steps"][0]["with"]["ref"]
            == "${{ github.event.pull_request.base.sha }}"
        )
        for lane in set(POLICY["scopes"]["full"]) - {"docs", "integrity"}:
            assert jobs[lane]["if"] == "needs.plan.outputs.scope == 'full'"
            child = yaml.safe_load((ROOT / jobs[lane]["uses"]).read_text())
            events = child.get("on", child.get(True))
            assert "workflow_call" in events
            assert "pull_request" not in events
            assert "draft" not in str(child)
