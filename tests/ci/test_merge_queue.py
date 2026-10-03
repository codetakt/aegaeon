"""Queue contexts, complete signature ranges, trusted policy and side effects."""

from __future__ import annotations

import ast
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from validate_change import (
    BOOTSTRAP_BASE,
    bootstrap_allowed,
    classify,
    context,
    run,
    verify_signatures,
)

ROOT = Path(__file__).resolve().parents[2]
BASE, PARENT, HEAD, MERGE = (character * 40 for character in "abcd")


def group():
    return {
        "action": "checks_requested",
        "merge_group": {
            "base_ref": "refs/heads/main",
            "head_ref": "refs/heads/gh-readonly-queue/main/pr-1",
            "base_sha": PARENT,
            "head_sha": HEAD,
        },
    }


def pr():
    return {
        "pull_request": {
            "base": {"ref": "main", "sha": BASE},
            "head": {"ref": "topic", "sha": HEAD, "repo": {"full_name": "owner/repo"}},
        },
        "repository": {"full_name": "owner/repo"},
    }


def graph(*args):
    if args[:2] == ("cat-file", "-t"):
        value = "commit"
    elif args == ("rev-parse", "HEAD"):
        value = HEAD
    elif args[0] == "rev-parse":
        value = "e" * 40
    elif args[:2] == ("merge-base", "--is-ancestor"):
        value = ""
    else:
        raise AssertionError(args)
    return value


def condition(expression, *, event, ref, private=False):
    """Evaluate only the boolean subset used by these publication conditions."""
    expression = expression.replace("${{", "").replace("}}", "").strip()
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = expression.replace("github.event.repository.private", repr(private))
    expression = expression.replace("github.event_name", repr(event))
    expression = expression.replace("github.ref", repr(ref)).replace("false", "False")

    def evaluate(node):
        if isinstance(node, ast.Constant):
            value = node.value
        elif isinstance(node, ast.BoolOp):
            values = [evaluate(child) for child in node.values]
            value = all(values) if isinstance(node.op, ast.And) else any(values)
        elif isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = evaluate(node.left), evaluate(node.comparators[0])
            value = left == right if isinstance(node.ops[0], ast.Eq) else left != right
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "startsWith":
                value = evaluate(node.args[0]).startswith(evaluate(node.args[1]))
            elif node.func.id == "always":
                value = True
            else:
                raise AssertionError(ast.dump(node))
        else:
            raise AssertionError(ast.dump(node))
        return value

    return evaluate(ast.parse(expression, mode="eval").body)


class ContextTests(unittest.TestCase):
    def test_group_records_speculative_parent_separately_from_authority(self):
        with patch("validate_change.git", side_effect=graph) as git:
            bound = context(group(), "merge_group", HEAD, BASE)
        assert bound["event_base"] == PARENT
        assert bound["base"] == BASE
        assert bound["source_head"] == bound["test_sha"] == HEAD
        assert ("merge-base", "--is-ancestor", BASE, HEAD) in [c.args for c in git.call_args_list]
        assert ("merge-base", "--is-ancestor", PARENT, HEAD) in [c.args for c in git.call_args_list]

    def test_pr_classifies_source_head_but_tests_merge(self):
        def pr_graph(*args):
            return MERGE if args == ("rev-parse", "HEAD") else graph(*args)

        with patch("validate_change.git", side_effect=pr_graph):
            bound = context(pr(), "pull_request", MERGE, BASE)
        assert bound["source_head"] == HEAD
        assert bound["test_sha"] == MERGE

    def test_missing_malformed_and_wrong_refs_fail_before_classification(self):
        cases = [
            ({}, "merge_group", HEAD, BASE),
            (group(), "push", HEAD, BASE),
            (group(), "merge_group", MERGE, BASE),
            (pr(), "pull_request", HEAD, PARENT),
        ]
        for field, value in [
            ("base_ref", "refs/heads/topic"),
            ("head_ref", "refs/heads/main"),
            ("base_sha", "short"),
            ("head_sha", "short"),
        ]:
            event = group()
            event["merge_group"][field] = value
            cases.append((event, "merge_group", HEAD, BASE))
        for args in cases:
            with (
                patch("validate_change.git", side_effect=graph),
                pytest.raises((KeyError, ValueError)),
            ):
                context(*args)

    def test_unavailable_object_and_stale_main_fail_closed(self):
        for failing in [("cat-file", "-t", PARENT), ("merge-base", "--is-ancestor", BASE, HEAD)]:

            def invalid(*args, failing=failing):
                if args == failing:
                    raise subprocess.CalledProcessError(1, ["git", *args])
                return graph(*args)

            with (
                patch("validate_change.git", side_effect=invalid),
                pytest.raises(subprocess.CalledProcessError),
            ):
                context(group(), "merge_group", HEAD, BASE)

    def test_bootstrap_is_only_exact_preparation_pr(self):
        event = pr()
        event["pull_request"]["head"]["ref"] = "ci/merge-queue-validation"
        bound = {"event": "pull_request", "base": BOOTSTRAP_BASE}
        assert bootstrap_allowed(event, bound)
        for field, value in [("event", "merge_group"), ("base", BASE)]:
            assert not bootstrap_allowed(event, {**bound, field: value})
        fork = copy.deepcopy(event)
        fork["pull_request"]["head"]["repo"]["full_name"] = "fork/repo"
        assert not bootstrap_allowed(fork, bound)


class SignatureTests(unittest.TestCase):
    def invoke(self, failure=None):
        def history(*args):
            if args == ("rev-list", "--reverse", f"{BASE}..{HEAD}"):
                return PARENT + "\n" + HEAD
            return graph(*args)

        def api(argv, **kwargs):
            sha = argv[-1].rsplit("/", 1)[-1]
            if failure == "api":
                raise subprocess.CalledProcessError(1, argv)
            verification = {"verified": True, "reason": "valid"}
            if sha == failure:
                verification = {"verified": False, "reason": "unsigned"}
            if failure == "reason":
                verification["reason"] = "unknown_key"
            if failure == "missing":
                verification = {}
            return json.dumps({"sha": sha, "commit": {"verification": verification}})

        with (
            patch("validate_change.git", side_effect=history),
            patch("validate_change.subprocess.check_output", side_effect=api),
        ):
            return verify_signatures(BASE, HEAD, "owner/repo")

    def test_every_introduced_commit_including_generated_parent_is_checked(self):
        assert [r["sha"] for r in self.invoke()] == [PARENT, HEAD]

    def test_non_head_generated_head_missing_bad_reason_and_api_fail(self):
        for failure in [PARENT, HEAD, "missing", "reason", "api"]:
            with pytest.raises((ValueError, subprocess.CalledProcessError)):
                self.invoke(failure)


class PolicyTests(unittest.TestCase):
    def test_classifier_loaded_from_protected_main_not_speculative_parent(self):
        legacy_policy = json.loads((ROOT / "ci/pr-policy.json").read_text())
        for key in (
            "component_plan_version",
            "components",
            "infrastructure_modules",
            "supplemental_lanes",
        ):
            legacy_policy.pop(key, None)
        classifier = (ROOT / "scripts/ci/pr_plan.py").read_bytes()
        policy = json.dumps(legacy_policy).encode()
        sources = {
            f"{BASE}:scripts/ci/pr_plan.py": classifier,
            f"{BASE}:ci/pr-policy.json": policy,
        }
        expected = {
            "version": 1,
            "base": BASE,
            "head": HEAD,
            "scope": "full",
            "selected": legacy_policy["scopes"]["full"],
            "changes": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "plan.json"

            def show(argv, **_kwargs):
                assert argv[:2] == ["git", "show"]
                return sources[argv[2]]

            def execute(argv, **kwargs):
                assert argv[argv.index("--base") + 1] == BASE
                assert argv[argv.index("--head") + 1] == HEAD
                assert Path(argv[1]).read_bytes() == classifier
                assert Path(argv[argv.index("--policy") + 1]).read_bytes() == policy
                assert "GITHUB_OUTPUT" not in kwargs["env"]
                output.write_text(json.dumps(expected))

            with (
                patch("validate_change.subprocess.check_output", side_effect=show) as reads,
                patch("validate_change.subprocess.run", side_effect=execute),
            ):
                result = classify({"base": BASE, "event_base": PARENT, "source_head": HEAD}, output)
            assert result == expected
            assert "component_plan" not in result
            assert [call.args[0] for call in reads.call_args_list] == [
                ["git", "show", f"{BASE}:scripts/ci/pr_plan.py"],
                ["git", "show", f"{BASE}:ci/pr-policy.json"],
            ]

    def test_missing_classifier_retains_full_fallback(self):
        with patch(
            "validate_change.subprocess.check_output",
            side_effect=subprocess.CalledProcessError(1, "git"),
        ):
            assert classify({"base": BASE, "source_head": HEAD}, Path("unused"))["scope"] == "full"


class RunTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        previous = Path.cwd()
        os.chdir(self.directory)
        self.addCleanup(os.chdir, previous)
        event = self.directory / "event.json"
        event.write_text(json.dumps(group()))
        self.output = self.directory / "outputs"
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    "GITHUB_EVENT_PATH": str(event),
                    "GITHUB_EVENT_NAME": "merge_group",
                    "GITHUB_SHA": HEAD,
                    "TRUSTED_BASE_SHA": BASE,
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_OUTPUT": str(self.output),
                },
            )
        )

    def test_failed_context_non_head_signature_or_api_emits_no_success_output(self):
        for failure in ["context", "non-head", "api"]:
            with (
                patch("validate_change.git", side_effect=graph),
                patch("validate_change.classify") as classify_mock,
                patch("validate_change.verify_signatures") as signatures,
            ):
                if failure == "context":
                    os.environ["GITHUB_SHA"] = MERGE
                elif failure == "non-head":
                    signatures.side_effect = ValueError(f"commit {PARENT} lacks valid signature")
                else:
                    signatures.side_effect = subprocess.CalledProcessError(1, "gh")
                with pytest.raises((ValueError, subprocess.CalledProcessError)):
                    run(bootstrap=False)
                classify_mock.assert_not_called()
                assert not self.output.exists()
                os.environ["GITHUB_SHA"] = HEAD

    def test_success_binds_context_signatures_and_policy_to_outputs(self):
        plan = {"scope": "full", "classifier_sha256": "1" * 64, "policy_sha256": "2" * 64}
        signatures = [
            {"sha": PARENT, "verified": True, "reason": "valid"},
            {"sha": HEAD, "verified": True, "reason": "valid"},
        ]
        with (
            patch("validate_change.git", side_effect=graph),
            patch("validate_change.classify", return_value=plan),
            patch("validate_change.verify_signatures", return_value=signatures),
        ):
            run(bootstrap=False)
        evidence = json.loads(Path("ci-validation.json").read_text())
        recorded_plan = json.loads(Path("ci-plan.json").read_text())
        assert evidence["base"] == recorded_plan["base"] == BASE
        assert evidence["event_base"] == PARENT
        assert evidence["test_sha"] == recorded_plan["test_sha"] == HEAD
        assert evidence["test_tree"] == recorded_plan["test_tree"] == "e" * 40
        assert recorded_plan["policy_sha256"] == "2" * 64
        assert evidence["signatures"] == signatures
        assert evidence["verifier_authority"] == "protected base"
        assert (
            self.output.read_text()
            == f"scope=full\nbase={BASE}\nsource_head={HEAD}\ntest_sha={HEAD}\n"
        )


class WorkflowTests(unittest.TestCase):
    def load(self, name):
        return yaml.safe_load((ROOT / f".github/workflows/{name}.yml").read_text())

    def test_group_trigger_authority_pin_and_aggregate(self):
        workflow = self.load("pr")
        assert workflow[True]["merge_group"] == {
            "branches": ["main"],
            "types": ["checks_requested"],
        }
        steps = workflow["jobs"]["plan"]["steps"]
        run = next(s["run"] for s in steps if s.get("id") == "plan")
        assert run.count('gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main"') == 1
        assert 'git show "$TRUSTED_BASE_SHA:scripts/ci/validate_change.py"' in run
        assert '[[ "$GITHUB_EVENT_NAME" == pull_request ]]' in run
        required = workflow["jobs"]["required"]["steps"]
        assert '[[ "$PLAN_RESULT" == success ]]' in required[0]["run"]
        assert required[1]["with"]["ref"] == "${{ needs.plan.outputs.base }}"

    def test_concurrency_has_distinct_workflow_event_and_group_keys(self):
        groups = []
        for name in [
            "pr",
            "ci",
            "lint",
            "compliance",
            "verification",
            "docker-build",
            "oidc-kms-parity",
        ]:
            key = self.load(name)["concurrency"]["group"]
            assert "github.event_name" in key
            assert "github.event.merge_group.head_ref" in key
            groups.append(key.split("${{")[0])
        assert len(groups) == len(set(groups))

    def test_container_publication_has_positive_event_and_ref_allowlist(self):
        steps = self.load("docker-build")["jobs"]["build-and-push"]["steps"]
        names = {
            "Log in to GitHub Container Registry",
            "Tag and push OCI image",
            "Output image info",
        }
        guards = [s["if"] for s in steps if s.get("name") in names]
        assert len(guards) == 3
        for guard in guards:
            for event in [
                "pull_request",
                "merge_group",
                "workflow_call",
                "schedule",
                "unknown",
                "push",
                "workflow_dispatch",
            ]:
                for ref in [
                    "refs/heads/main",
                    "refs/tags/v1.0",
                    "refs/tags/other",
                    "refs/heads/topic",
                    "refs/heads/gh-readonly-queue/main/pr-1",
                ]:
                    expected = event in {"push", "workflow_dispatch"} and ref in {
                        "refs/heads/main",
                        "refs/tags/v1.0",
                    }
                    assert condition(guard, event=event, ref=ref) == expected

    def test_group_compliance_matches_pr_and_attestation_requires_main_event(self):
        jobs = self.load("compliance")["jobs"]
        for job in jobs.values():
            if "!= 'pull_request'" in job.get("if", ""):
                assert "!= 'merge_group'" in job["if"]
        attestation = next(
            s for s in jobs["sbom-generation"]["steps"] if "actions/attest@" in s.get("uses", "")
        )
        assert "github.ref == 'refs/heads/main'" in attestation["if"]
        assert all(
            f"github.event_name == '{event}'" in attestation["if"]
            for event in ["push", "workflow_dispatch", "schedule"]
        )

    def test_group_and_pr_compliance_select_the_same_jobs(self):
        for job in self.load("compliance")["jobs"].values():
            guard = job.get("if", "True")
            assert condition(
                guard, event="merge_group", ref="refs/heads/gh-readonly-queue/main/pr-1"
            ) == condition(guard, event="pull_request", ref="refs/pull/1/merge")

    def test_attestation_rejects_group_unknown_and_non_main_refs(self):
        job = self.load("compliance")["jobs"]["sbom-generation"]
        step = next(s for s in job["steps"] if "actions/attest@" in s.get("uses", ""))
        for event in [
            "pull_request",
            "merge_group",
            "workflow_call",
            "unknown",
            "push",
            "workflow_dispatch",
            "schedule",
        ]:
            for ref in ["refs/heads/main", "refs/tags/v1", "refs/heads/topic"]:
                for private in [False, True]:
                    expected = (
                        event in {"push", "workflow_dispatch", "schedule"}
                        and ref == "refs/heads/main"
                        and not private
                    )
                    assert condition(step["if"], event=event, ref=ref, private=private) == expected

    def test_called_workflows_do_not_retain_checkout_credentials(self):
        for name in [
            "pr",
            "ci",
            "lint",
            "compliance",
            "security",
            "verification",
            "docker-build",
            "oidc-kms-parity",
        ]:
            for job in self.load(name)["jobs"].values():
                for step in job.get("steps", []):
                    if "actions/checkout@" in step.get("uses", ""):
                        assert step["with"]["persist-credentials"] is False

    def test_group_docs_lints_range_without_fabricating_title(self):
        script = (ROOT / "scripts/ci/run_docs.sh").read_text()
        assert 'scripts/commitlint-range.sh --from "$PR_BASE_SHA" --to "$PR_HEAD_SHA"' in script
        assert "if [[ $GITHUB_EVENT_NAME == pull_request ]]; then" in script
