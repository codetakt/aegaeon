"""Regression tests for check selection, aggregate failures and local file links."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from check_doc_links import broken_links, local_links, snapshot
from check_pr_results import check_results
from pr_plan import build_plan, classify, path_scope, unique_json_object, validate_policy
from validate_change import classify as classify_change

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


class SupplementalAggregateTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))

    def test_pending_and_required_presence_for_every_scope(self):
        for scope in POLICY["scopes"]:
            for state in ["pending", "required"]:
                policy = deepcopy(POLICY)
                policy["supplemental_lanes"] = {"components": state}
                needs = results(scope)
                if state == "pending":
                    check_results(needs, policy)
                else:
                    with pytest.raises(ValueError, match="missing required supplemental"):
                        check_results(needs, policy)
                needs["components"] = {"result": "success"}
                check_results(needs, policy)
                for outcome in ["failure", "skipped", "cancelled", "neutral", "", None, [], {}]:
                    needs["components"] = {"result": outcome}
                    with (
                        self.subTest(scope=scope, state=state, outcome=outcome),
                        pytest.raises(ValueError, match="supplemental check must succeed"),
                    ):
                        check_results(needs, policy)
                needs["components"] = {}
                with pytest.raises(ValueError, match="supplemental check must succeed"):
                    check_results(needs, policy)

    def test_supplemental_success_cannot_replace_any_original_check(self):
        for scope in POLICY["scopes"]:
            for state in ["pending", "required"]:
                policy = deepcopy(POLICY)
                policy["supplemental_lanes"] = {"components": state}
                for lane in POLICY["scopes"]["full"]:
                    needs = results(scope)
                    needs["components"] = {"result": "success"}
                    del needs[lane]
                    with pytest.raises(ValueError, match="check inventory"):
                        check_results(needs, policy)
                    for outcome in ["failure", "cancelled", None]:
                        needs[lane] = {"result": outcome}
                        with pytest.raises(ValueError, match=rf"^{lane}:"):
                            check_results(needs, policy)
                    needs[lane] = {"result": "skipped"}
                    if lane in policy["scopes"][scope]:
                        with pytest.raises(ValueError, match=rf"^{lane}:"):
                            check_results(needs, policy)
                    else:
                        check_results(needs, policy)

    def test_legacy_policy_does_not_authorize_an_unregistered_lane(self):
        policy = deepcopy(POLICY)
        del policy["supplemental_lanes"]
        for scope in POLICY["scopes"]:
            needs = results(scope)
            check_results(needs, policy)
            needs["components"] = {"result": "success"}
            with pytest.raises(ValueError, match="check inventory"):
                check_results(needs, policy)

    def test_unknown_needs_and_malformed_result_shapes_reject(self):
        needs = results("docs")
        needs["other"] = {"result": "success"}
        with pytest.raises(ValueError, match="check inventory"):
            check_results(needs, POLICY)
        for value in [None, [], "success", 1]:
            with pytest.raises(ValueError, match="JSON object"):
                check_results(value, POLICY)
            for lane in ["plan", "docs", "components"]:
                needs = results("docs")
                needs[lane] = value
                with pytest.raises(ValueError, match="result object"):
                    check_results(needs, POLICY)
        for outputs in [None, [], "docs", {"scope": []}, {"scope": None}]:
            needs = results("docs")
            needs["plan"]["outputs"] = outputs
            with pytest.raises(ValueError, match=r"classification|Classification"):
                check_results(needs, POLICY)

    def test_policy_rejects_unknown_overlap_duplicate_and_invalid_state(self):
        for supplemental in [
            None,
            [],
            "pending",
            {"components": "optional"},
            {"components": None},
            {"components": []},
            {"components": True},
            {"other": "pending"},
            {"docs": "pending"},
            {"plan": "pending"},
        ]:
            policy = deepcopy(POLICY)
            policy["supplemental_lanes"] = supplemental
            with pytest.raises(ValueError, match="supplemental"):
                validate_policy(policy)
            with pytest.raises(ValueError, match="supplemental"):
                check_results(results("full"), policy)
        for full in [
            [],
            ["docs", "integrity"],
            [*POLICY["scopes"]["full"], "components"],
            [*POLICY["scopes"]["full"], "core"],
            "full",
            None,
        ]:
            policy = deepcopy(POLICY)
            policy["scopes"]["full"] = full
            with pytest.raises(ValueError, match="original full-check inventory"):
                validate_policy(policy)
        for policy in [
            None,
            [],
            {"version": True, "scopes": POLICY["scopes"]},
            {"version": 1, "scopes": []},
        ]:
            with pytest.raises(ValueError, match=r"policy|scopes"):
                validate_policy(policy)
        for raw in [
            '{"components":"pending","components":"required"}',
            '{"docs":{"result":"failure"},"docs":{"result":"success"}}',
            '{"version":1,"version":1}',
        ]:
            with pytest.raises(ValueError, match="duplicate JSON key"):
                json.loads(raw, object_pairs_hook=unique_json_object)

    def test_classification_and_workflow_inventory_remain_original(self):
        expected = [
            "docs",
            "integrity",
            "core",
            "lint",
            "security",
            "verification",
            "compliance",
            "kms",
            "container",
        ]
        assert POLICY["scopes"] == {
            "docs": ["docs"],
            "integrity": ["docs", "integrity"],
            "full": expected,
        }
        assert POLICY["supplemental_lanes"] == {"components": "pending"}
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        assert set(workflow["jobs"]["required"]["needs"]) == {"plan", *expected}
        assert "components" not in workflow["jobs"]
        for path, scope in [
            ("SECURITY.md", "docs"),
            ("spec/compliance-matrix.yaml", "integrity"),
            ("examples/minimal-rp/requirements.txt", "full"),
        ]:
            plan = classify([change(path)], POLICY)
            assert plan["scope"] == scope
            assert plan["selected"] == POLICY["scopes"][scope]

    def test_cli_malformed_json_reports_a_clear_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            policy_path.write_text(json.dumps(POLICY))
            cases = [
                "not-json",
                "[]",
                '{"plan":null}',
                '{"plan":{"result":"success","outputs":{"scope":[]}}}',
                '{"plan":{},"plan":{}}',
            ]
            for raw in cases:
                result = subprocess.run(  # noqa: S603 - fixed checker and isolated JSON input
                    [
                        sys.executable,
                        str(ROOT / "scripts/ci/check_pr_results.py"),
                        "--policy",
                        str(policy_path),
                    ],
                    env={**os.environ, "PR_NEEDS_JSON": raw},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert result.returncode == 1
                assert "PR validation failed:" in result.stdout
                assert "Traceback" not in result.stderr


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
        if self._testMethodName != (
            "test_group_delta_uses_protected_policy_and_includes_earlier_runtime_change"
        ):
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

    def test_group_delta_uses_protected_policy_and_includes_earlier_runtime_change(self):  # noqa: PLR0915
        # Real index, blobs, trees and NUL diffs; only ancestry/commit identities
        # are modeled. No fixture commit objects or signature evidence are created.
        protected_paths = (
            "scripts/ci/pr_plan.py",
            "scripts/ci/validate_change.py",
            "scripts/ci/verify_ci_plan.py",
            "ci/pr-policy.json",
            "ci/ci-plan.schema.json",
            "ci/ci-input-union.schema.json",
            "ci/ci-input-authority.json",
            "ci/ci-expected-inventory.json",
            "ci/ci-result-contract.json",
        )
        for path in protected_paths:
            self.write(path, (ROOT / path).read_text())
        classifier = (ROOT / "scripts/ci/pr_plan.py").read_bytes()
        policy = (ROOT / "ci/pr-policy.json").read_bytes()
        identities = [character * 40 for character in "abc"]
        trees = {}

        def capture_tree(identity):
            self.git("add", "--force", ".")
            trees[identity] = self.git("write-tree")
            return identity

        protected_base = capture_tree(identities[0])
        self.write("implementation.rs", "fn main() { todo!() }\n")
        for path in protected_paths:
            self.write(path, "raise RuntimeError('candidate authority executed')\n")
        speculative_parent = capture_tree(identities[1])
        self.write("docs/queued.md", "Later queued documentation\n")
        group_head = capture_tree(identities[2])
        tools = Path(self.enterContext(tempfile.TemporaryDirectory()))
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)  # noqa: PT009 - active under Python -O
        wrapper = tools / "git"
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            f"real_git = {real_git!r}\n"
            f"trees = {trees!r}\n"
            f"identities = {identities!r}\n"
            "args = sys.argv[1:]\n"
            "start = 0\n"
            "while start < len(args):\n"
            "    if args[start] == '--no-replace-objects': start += 1\n"
            "    elif args[start] in ('-C', '-c'): start += 2\n"
            "    else: break\n"
            "operation = args[start:]\n"
            "if operation[0] == 'merge-base':\n"
            "    pair = operation[-2:]\n"
            "    if any(value not in identities for value in pair): sys.exit(91)\n"
            "    if operation[1] == '--is-ancestor':\n"
            "        sys.exit(0 if identities.index(pair[0]) <= identities.index(pair[1]) else 1)\n"
            "    print(min(pair, key=identities.index)); sys.exit(0)\n"
            "if operation[0] == 'fetch':\n"
            "    expected = ['fetch', '--no-tags', 'origin', identities[0]]\n"
            "    sys.exit(0 if operation == expected else 92)\n"
            "if operation == ['rev-parse', 'HEAD']:\n"
            "    print(identities[-1]); sys.exit(0)\n"
            "if operation[0] == 'rev-list':\n"
            "    expected = ['rev-list', '--reverse', identities[0] + '..' + identities[-1]]\n"
            "    if operation != expected: sys.exit(93)\n"
            "    print('\\n'.join(identities[1:])); sys.exit(0)\n"
            "if (operation[:2] == ['cat-file', '-t']\n"
            "        and len(operation) == 3 and operation[2] in trees):\n"
            "    print('commit'); sys.exit(0)\n"
            "def resolve(value):\n"
            "    if value == 'HEAD^{tree}': return trees[identities[-1]]\n"
            "    if value.endswith('^{tree}') and value[:-7] in trees: return trees[value[:-7]]\n"
            "    if ':' in value and value.split(':', 1)[0] in trees:\n"
            "        identity, path = value.split(':', 1); return trees[identity] + ':' + path\n"
            "    return trees.get(value, value)\n"
            "args[start + 1:] = [resolve(value) for value in operation[1:]]\n"
            "os.execv(real_git, [real_git, *args])\n"
        )
        wrapper.chmod(0o755)
        event = self.repo / "event.json"
        event.write_text("{}\n")
        with patch.dict(
            os.environ,
            {
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "GITHUB_EVENT_PATH": str(event),
                "GITHUB_REPOSITORY": "codetakt/aegaeon",
                "GITHUB_RUN_ID": "1",
                "GITHUB_RUN_ATTEMPT": "1",
            },
        ):
            self.assertEqual(  # noqa: PT009 - active under Python -O
                build_plan(self.repo, speculative_parent, group_head, POLICY)["scope"], "docs"
            )
            previous = Path.cwd()
            os.chdir(self.repo)
            try:
                plan = classify_change(
                    {
                        "event": "merge_group",
                        "event_base": speculative_parent,
                        "base": protected_base,
                        "source_head": group_head,
                        "test_sha": group_head,
                        "test_tree": trees[group_head],
                    },
                    self.repo / "group-plan.json",
                )
            finally:
                os.chdir(previous)
            self.assertEqual(plan["scope"], "full")  # noqa: PT009 - active under Python -O
            self.assertEqual(  # noqa: PT009 - active under Python -O
                {record["path"] for record in plan["changes"]},
                {"implementation.rs", "docs/queued.md", *protected_paths},
            )
            self.assertEqual(plan["classifier_sha256"], hashlib.sha256(classifier).hexdigest())  # noqa: PT009 - active under Python -O
            self.assertEqual(plan["policy_sha256"], hashlib.sha256(policy).hexdigest())  # noqa: PT009 - active under Python -O
            union = json.loads((self.repo / "ci-input-union.json").read_text())
            self.assertEqual(union["test_tree"], trees[group_head])  # noqa: PT009 - active under Python -O
            self.assertEqual(  # noqa: PT009 - active under Python -O
                plan["input_union"]["sha256"],
                hashlib.sha256((self.repo / "ci-input-union.json").read_bytes()).hexdigest(),
            )
            self.assertEqual(  # noqa: PT009 - active under Python -O
                {entry["decoded_path"] for entry in union["entries"]},
                {"SECURITY.md", "implementation.rs", "docs/queued.md", *protected_paths},
            )
            raw = subprocess.check_output(  # noqa: S603 - fixed literal Git tree diff
                [
                    real_git,
                    "-C",
                    str(self.repo),
                    "diff",
                    "--raw",
                    "-z",
                    "--no-abbrev",
                    "--no-renames",
                    "--ignore-submodules=none",
                    "--no-ext-diff",
                    "--no-textconv",
                    trees[protected_base],
                    trees[group_head],
                    "--",
                ]
            )
            self.assertEqual(  # noqa: PT009 - active under Python -O
                base64.b64decode(union["raw_diff"]["raw_base64"]), raw
            )
            self.assertEqual(  # noqa: PT009 - active under Python -O
                union["raw_diff"]["sha256"], hashlib.sha256(raw).hexdigest()
            )
            for entry in union["entries"]:
                for side, identity in (
                    ("base", protected_base),
                    ("head", group_head),
                    ("tested", group_head),
                ):
                    self.assertEqual(entry[side]["tree"], trees[identity])  # noqa: PT009
                    if entry[side]["present"]:
                        content = subprocess.check_output(  # noqa: S603 - actual tree bytes
                            [
                                real_git,
                                "-C",
                                str(self.repo),
                                "show",
                                trees[identity] + ":" + entry["decoded_path"],
                            ]
                        )
                        self.assertEqual(  # noqa: PT009 - active under Python -O
                            entry[side]["sha256"], hashlib.sha256(content).hexdigest()
                        )
            # The actual workflow rejects reserved outputs, so start it clean.
            (self.repo / "ci-input-union.json").unlink()
            self.check_group_workflow(protected_base, speculative_parent, group_head)

    def check_group_workflow(self, protected_base, speculative_parent, group_head):
        # Execute the actual workflow and protected reader. API signatures and
        # commit ancestry are synthetic; tree/blob/diff operations remain real.
        tools = self.repo / "fake-tools"
        tools.mkdir()
        gh = tools / "gh"
        gh.write_text(
            f"#!{sys.executable}\nimport json, os, sys\n"
            f"base = {protected_base!r}\n"
            "mode = os.environ.get('FAKE_API_MODE')\n"
            "if mode == 'network':\n    sys.exit(1)\n"
            "if mode == 'missing-main' and sys.argv[-1] == '.object.sha':\n"
            "    print('null'); sys.exit(0)\n"
            "if sys.argv[-1] == '.object.sha':\n    print(base)\n"
            "else:\n    sha = sys.argv[-1].rsplit('/', 1)[-1]\n"
            "    print(json.dumps({'sha': sha, 'commit': {'verification': "
            "{'verified': mode != 'unsigned', 'reason': 'valid'}}}))\n"
        )
        gh.chmod(0o755)
        event_path = self.repo / "event.json"
        event_path.write_text(
            json.dumps(
                {
                    "action": "checks_requested",
                    "merge_group": {
                        "base_sha": speculative_parent,
                        "head_sha": group_head,
                        "base_ref": "refs/heads/main",
                        "head_ref": "refs/heads/gh-readonly-queue/main/pr-1",
                    },
                }
            )
        )
        self.git("remote", "add", "origin", str(self.repo))
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        command = next(
            step["run"] for step in workflow["jobs"]["plan"]["steps"] if step.get("id") == "plan"
        )
        output = self.repo / "github-output"
        env = {
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "GITHUB_EVENT_NAME": "merge_group",
            "GITHUB_SHA": group_head,
            "GITHUB_REPOSITORY": "codetakt/aegaeon",
            "GITHUB_EVENT_PATH": str(event_path),
            "GITHUB_OUTPUT": str(output),
            "RUNNER_TEMP": str(tools),
            "EVENT_BASE_SHA": speculative_parent,
        }
        result = subprocess.run(  # noqa: S603 - fixed workflow with synthetic API and Git fixture
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command],  # noqa: S607
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009
        evidence = json.loads((self.repo / "ci-validation.json").read_text())
        self.assertEqual(evidence["base"], protected_base)  # noqa: PT009
        self.assertEqual(evidence["event_base"], speculative_parent)  # noqa: PT009
        self.assertEqual(evidence["test_tree"], self.git("rev-parse", "HEAD^{tree}"))  # noqa: PT009
        self.assertEqual(  # noqa: PT009
            {record["sha"] for record in evidence["signatures"]},
            {speculative_parent, group_head},
        )
        self.assertTrue(  # noqa: PT009
            output.read_text().startswith(f"scope=full\nbase={protected_base}\n")
        )
        for failure in ["network", "missing-main", "unsigned"]:
            output.unlink(missing_ok=True)
            for artifact in ("ci-plan.json", "ci-validation.json", "ci-input-union.json"):
                (self.repo / artifact).unlink(missing_ok=True)
            failed = subprocess.run(  # noqa: S603 - same isolated workflow/API fixture
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command],  # noqa: S607
                cwd=self.repo,
                env={**env, "FAKE_API_MODE": failure},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0, failure)  # noqa: PT009
            self.assertFalse(output.exists(), failure)  # noqa: PT009

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
        assert events["pull_request"]["types"] == ["opened", "synchronize", "reopened", "edited"]
        jobs = workflow["jobs"]
        assert set(jobs["required"]["needs"]) == set(POLICY["scopes"]["full"]) | {"plan"}
        assert "always()" in jobs["required"]["if"]
        assert jobs["required"]["steps"][1]["with"]["ref"] == "${{ needs.plan.outputs.base }}"
        for lane in set(POLICY["scopes"]["full"]) - {"docs", "integrity"}:
            assert jobs[lane]["if"] == "needs.plan.outputs.scope == 'full'"
            child = yaml.safe_load((ROOT / jobs[lane]["uses"]).read_text())
            events = child.get("on", child.get(True))
            assert "workflow_call" in events
            assert "pull_request" not in events
            assert "draft" not in str(child)

    def test_documentation_parallel_workers_keep_complete_gate(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        jobs = workflow["jobs"]
        assert jobs["docs"]["needs"] == "plan"
        assert "if" not in jobs["docs"]
        assert jobs["docs"]["uses"] == "./.github/workflows/documentation.yml"
        assert jobs["docs"]["with"] == {
            "base": "${{ needs.plan.outputs.base }}",
            "source-head": "${{ needs.plan.outputs.source_head }}",
            "test-sha": "${{ needs.plan.outputs.test_sha }}",
            "pr-title": "${{ github.event.pull_request.title || '' }}",
            "pr-author": "${{ github.event.pull_request.user.login || '' }}",
        }
        docs = yaml.safe_load((ROOT / jobs["docs"]["uses"]).read_text())
        assert set(docs["jobs"]) == {"metadata", "helpers", "complete"}
        assert set(docs.get("on", docs.get(True))) == {"workflow_call"}
        assert docs["permissions"] == {"contents": "read"}
        assert docs["jobs"]["helpers"]["strategy"]["matrix"]["group"] == [
            "sanitizer",
            "security-fuzz",
            "other",
        ]
        assert docs["jobs"]["helpers"]["strategy"]["fail-fast"] is False
        assert docs["jobs"]["helpers"]["strategy"]["max-parallel"] == 3
        for job in ("helpers", "complete"):
            command = next(step["run"] for step in docs["jobs"][job]["steps"] if "run" in step)
            assert command.index("nix develop .#docs --command bash -c") < command.index(
                "PYTHONPATH="
            )
        assert "if" not in docs["jobs"]["metadata"]
        assert "if" not in docs["jobs"]["helpers"]
        assert "always()" in docs["jobs"]["complete"]["if"]
        assert set(docs["jobs"]["complete"]["needs"]) == {"metadata", "helpers"}
        for job in docs["jobs"].values():
            assert job["timeout-minutes"] == 30
            checkout = job["steps"][0]["with"]
            assert checkout["persist-credentials"] is False
            assert checkout["ref"] == "${{ inputs.test-sha }}"
