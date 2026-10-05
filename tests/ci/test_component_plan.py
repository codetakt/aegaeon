"""Additive component selection and protected-source output controls."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest assertions must remain active under Python -O.
import hashlib
import json
import os
import runpy
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import test_merge_queue
import validate_change
from pr_plan import (
    COMPONENTS,
    INFRASTRUCTURE_MODULES,
    build_plan,
    classify,
    parse_changes,
    validate_policy,
)
from validate_change import validate_component_plan

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "ci/pr-policy.json").read_text())


def change(path, status="M", old_mode="100644", new_mode="100644"):
    return {"path": path, "status": status, "old_mode": old_mode, "new_mode": new_mode}


def plan(*changes):
    result = classify(list(changes), POLICY)
    validate_component_plan(result, POLICY)
    return result


def legacy_policy_bytes():
    policy = json.loads((ROOT / "ci/pr-policy.json").read_bytes())
    policy.pop("plan_envelope_version", None)
    return json.dumps(policy).encode()


class ComponentPlanTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(TemporaryDirectory()))

    def change_directory(self, directory):
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(directory)

    def set_environment(self, name, value):
        self.enterContext(patch.dict(os.environ, {name: value}))

    def test_exact_inputs(self):
        for path, components, modules in [
            ("examples/minimal-rp/requirements.txt", ["python-example"], []),
            ("examples/minimal-rp/app.py", ["python-example"], []),
            ("tests/examples/minimal_rp/check_flow.py", ["python-example"], []),
            ("scripts/oidf_conformance/suite/Dockerfile", ["conformance"], []),
            ("tests/ci/test_conformance_runner.py", ["conformance"], []),
            (".github/workflows/oidf-conformance.yml", ["conformance", "development-tools"], []),
            ("crates/server/tests/process_local_runtime_state_guard_test.rs", ["conformance"], []),
            ("package-lock.json", ["development-tools"], []),
            ("package.json", ["development-tools"], []),
            ("tsconfig.json", ["development-tools"], []),
            ("spec/server-strict-types.current.json", ["development-tools"], []),
            (
                "tests/verified_core_wasm/workflow_inventory_policy_test.ts",
                ["development-tools"],
                [],
            ),
            ("SECURITY.md", [], []),
            ("docs/verification/claims/check.md", [], []),
            *[
                (f"infra/tofu/{module}/{name}", ["infrastructure"], [module])
                for module in INFRASTRUCTURE_MODULES
                for name in ["main.tf", ".terraform.lock.hcl", "user_data.sh.tftpl"]
            ],
        ]:
            with self.subTest(path=path, components=components, modules=modules):
                result = plan(change(path))
                self.assertEqual(result["component_plan"]["components"], components)
                self.assertEqual(result["component_plan"]["infrastructure_modules"], modules)
                self.assertEqual(result["selected"], POLICY["scopes"][result["scope"]])
                if components:
                    self.assertEqual(result["scope"], "full")

    def test_overlapping_workflow_retains_all_consumers_and_complete_record(self):
        for status, old, new in [
            ("A", "000000", "100644"),
            ("D", "100644", "000000"),
            ("M", "100644", "100644"),
        ]:
            with self.subTest(status=status, old=old, new=new):
                workflow = change(".github/workflows/oidf-conformance.yml", status, old, new)
                result = plan(workflow)
                self.assertEqual(
                    result["component_plan"]["components"], ["conformance", "development-tools"]
                )
                self.assertEqual(result["component_plan"]["infrastructure_modules"], [])
                records = result["component_plan"]["changes"]
                self.assertEqual(len(records), 1)
                self.assertEqual({key: records[0][key] for key in workflow}, workflow)
                self.assertEqual(records[0]["components"], ["conformance", "development-tools"])
                self.assertIn("conformance suite", records[0]["reason"])
                self.assertIn("TypeScript consumer", records[0]["reason"])

    def test_unknown_shared_and_ambiguous_inputs_select_all(self):
        for path in [
            "flake.nix",
            "flake.lock",
            "rust-toolchain.toml",
            "nix/flake/checks.nix",
            ".github/actions/setup-nix-ci/action.yml",
            ".github/workflows/pr.yml",
            "ci/pr-policy.json",
            "scripts/ci/pr_plan.py",
            "scripts/ci/validate_python_example.py",
            "examples/minimal-rp/README.md",
            "examples/minimal-rp/unknown.py",
            "README.md",
            "infra/tofu/unknown/main.tf",
            "infra/tofu/perf-aws-ec2/unknown.json",
            "infra/tofu/perf-aws-ec2/nested/main.tf",
            "unknown.java",
            "docs/configurations/environment/a.md",
            "../docs/a.md",
            "docs//a.md",
            "docs/a\n.md",
            "docs/./a.md",
            "",
        ]:
            with self.subTest(path=path):
                result = plan(change(path)) if path else classify([change(path)], POLICY)
                self.assertEqual(result["scope"], "full")
                self.assertEqual(result["component_plan"]["components"], list(COMPONENTS))
                self.assertEqual(
                    result["component_plan"]["infrastructure_modules"], list(INFRASTRUCTURE_MODULES)
                )

    def test_add_delete_modify_preserve_targets(self):
        for status, old, new in [
            ("A", "000000", "100644"),
            ("D", "100644", "000000"),
            ("M", "100644", "100644"),
        ]:
            with self.subTest(status=status, old=old, new=new):
                self.assertEqual(
                    plan(change("examples/minimal-rp/app.py", status, old, new))["component_plan"][
                        "components"
                    ],
                    ["python-example"],
                )

    def test_mode_anomalies_select_all(self):
        for old, new in [
            ("100644", "100755"),
            ("120000", "120000"),
            ("000000", "160000"),
            ("000000", "000000"),
        ]:
            with self.subTest(old=old, new=new):
                self.assertEqual(
                    plan(change("examples/minimal-rp/app.py", "T", old, new))["component_plan"][
                        "components"
                    ],
                    list(COMPONENTS),
                )

    def test_empty_mixed_cumulative_and_rename_union(self):
        self.assertEqual(plan()["component_plan"]["components"], list(COMPONENTS))
        python = change("examples/minimal-rp/app.py", "D", "100644", "000000")
        infra = change("infra/tofu/perf-aws-ec2/main.tf", "A", "000000", "100644")
        docs = change("SECURITY.md")
        mixed = plan(infra, docs, python)
        self.assertEqual(
            mixed["component_plan"]["components"], ["infrastructure", "python-example"]
        )
        self.assertEqual(mixed["component_plan"], plan(python, infra, docs)["component_plan"])
        self.assertEqual(
            plan(python, infra, change("unknown"))["component_plan"]["components"], list(COMPONENTS)
        )
        self.assertNotEqual(
            plan(python, infra)["component_plan"]["components"],
            plan(infra)["component_plan"]["components"],
        )

    def test_bad_policy_rejected(self):
        for field, value in [
            ("component_plan_version", True),
            ("component_plan_version", 2),
            ("components", []),
            ("components", ["unknown"]),
            ("infrastructure_modules", ["unknown"]),
        ]:
            with self.subTest(field=field, value=value):
                policy = deepcopy(POLICY)
                policy[field] = value
                diagnostic = (
                    "^invalid protected full plan envelope version$"
                    if field == "component_plan_version" and value == 2
                    else "component"
                )
                with self.assertRaisesRegex(ValueError, diagnostic):
                    validate_policy(policy)
                with self.assertRaisesRegex(ValueError, "component"):
                    validate_component_plan(plan(), policy)

    def test_malformed_and_incomplete_outputs_rejected(self):
        baseline = plan(change("examples/minimal-rp/app.py"))
        cases = []
        missing = deepcopy(baseline)
        del missing["component_plan"]
        cases.append(missing)
        for key, value in [
            ("version", True),
            ("version", 2),
            ("components", []),
            ("components", ["unknown"]),
            ("components", ["python-example", "python-example"]),
            ("infrastructure_modules", ["perf-aws-ec2"]),
            ("infrastructure_modules", ["unknown"]),
            ("components", ["python-example", "infrastructure"]),
            ("changes", []),
            ("fallback", None),
        ]:
            mutated = deepcopy(baseline)
            mutated["component_plan"][key] = value
            cases.append(mutated)
        mutated = deepcopy(baseline)
        mutated["component_plan"]["changes"][0]["path"] = "other"
        cases.append(mutated)
        for mutated in cases:
            with self.assertRaisesRegex(ValueError, "component|infrastructure"):
                validate_component_plan(mutated, POLICY)
        for parser in [validate_change.unique_json_object]:
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                json.loads('{"version":1,"version":1}', object_pairs_hook=parser)

    def test_raw_diff_rejects_incomplete_duplicate_and_unsupported_records(self):
        record = b":100644 100644 1234567 2345678 M\x00examples/minimal-rp/app.py\x00"
        self.assertEqual(len(parse_changes(record)), 1)
        for invalid in [
            record[:-1],
            record + record,
            record.replace(b" M", b" R100"),
            record.replace(b"100644", b"garbage"),
        ]:
            with self.assertRaisesRegex(ValueError, "Git"):
                parse_changes(invalid)

    def test_classifier_cli_failure_keeps_all_targets(self):
        policy = self.directory / "policy.json"
        policy.write_text(json.dumps(POLICY))
        output = self.directory / "plan.json"
        subprocess.run(  # noqa: S603 - fixed classifier and isolated JSON arguments
            [
                sys.executable,
                str(ROOT / "scripts/ci/pr_plan.py"),
                "--base",
                "invalid",
                "--head",
                "invalid",
                "--policy",
                str(policy),
                "--output",
                str(output),
            ],
            check=True,
            capture_output=True,
        )
        result = json.loads(output.read_text())
        validate_component_plan(result, POLICY)
        self.assertEqual(result["scope"], "full")
        self.assertEqual(result["component_plan"]["components"], list(COMPONENTS))

    def test_output_published_only_after_context_and_signatures(self):
        self.change_directory(self.directory)
        event = self.directory / "event.json"
        event.write_text("{}")
        output = self.directory / "output"
        self.set_environment("GITHUB_EVENT_PATH", str(event))
        self.set_environment("GITHUB_EVENT_NAME", "merge_group")
        self.set_environment("GITHUB_SHA", "a" * 40)
        self.set_environment("TRUSTED_BASE_SHA", "b" * 40)
        self.set_environment("GITHUB_REPOSITORY", "owner/repo")
        self.set_environment("GITHUB_OUTPUT", str(output))
        bound = {
            "base": "b" * 40,
            "source_head": "a" * 40,
            "test_sha": "a" * 40,
            "test_tree": "c" * 40,
        }
        with (
            patch.object(validate_change, "context", return_value=bound),
            patch.object(
                validate_change, "verify_signatures", side_effect=ValueError("bad signature")
            ),
            self.assertRaisesRegex(ValueError, "bad signature"),
        ):
            validate_change.run(bootstrap=False)
        self.assertFalse(output.exists())
        classified = plan(change("package.json"))
        classified["component_plan_provenance"] = {
            **bound,
            "classifier_sha256": "1" * 64,
            "policy_sha256": "2" * 64,
        }
        with (
            patch.object(validate_change, "context", return_value=bound),
            patch.object(validate_change, "verify_signatures", return_value=[]),
            patch.object(validate_change, "classify", return_value=classified),
        ):
            validate_change.run(bootstrap=False)
        lines = output.read_text().splitlines()
        component_lines = [
            line.removeprefix("component_targets=")
            for line in lines
            if line.startswith("component_targets=")
        ]
        self.assertEqual(len(component_lines), 1)
        self.assertEqual(json.loads(component_lines[0])["components"], ["development-tools"])
        outputs = dict(line.split("=", 1) for line in lines)
        self.assertEqual(
            json.loads(outputs["component_plan_provenance"]),
            classified["component_plan_provenance"],
        )

    def test_protected_classifier_ignores_candidate_policy_and_binds_source(self):
        source = (ROOT / "scripts/ci/pr_plan.py").read_bytes()
        policy = legacy_policy_bytes()
        (self.directory / "scripts/ci").mkdir(parents=True)
        (self.directory / "ci").mkdir()
        (self.directory / "scripts/ci/pr_plan.py").write_text(
            'raise RuntimeError("candidate executed")'
        )
        (self.directory / "ci/pr-policy.json").write_text('{"components":[]}')
        self.change_directory(self.directory)
        self.set_environment("GITHUB_OUTPUT", str(self.directory / "output"))
        bound = {
            "base": "b" * 40,
            "source_head": "a" * 40,
            "test_sha": "c" * 40,
            "test_tree": "d" * 40,
        }

        def protected_read(argv, **_kwargs):
            self.assertEqual(argv[:2], ["git", "show"])
            return {
                bound["base"] + ":scripts/ci/pr_plan.py": source,
                bound["base"] + ":ci/pr-policy.json": policy,
            }[argv[2]]

        def protected_execution(argv, **kwargs):
            self.assertNotIn("GITHUB_OUTPUT", kwargs["env"])
            script = Path(argv[2])
            trusted_policy = Path(argv[argv.index("--policy") + 1])
            self.assertEqual((argv[1], script.read_bytes()), ("-I", source))
            self.assertEqual(trusted_policy.read_bytes(), policy)
            protected = runpy.run_path(str(script))
            result = protected["classify"](
                [change("examples/minimal-rp/app.py")], json.loads(policy)
            )
            result.update(
                {
                    "base": bound["base"],
                    "head": bound["source_head"],
                    "classifier_sha256": hashlib.sha256(source).hexdigest(),
                    "policy_sha256": hashlib.sha256(policy).hexdigest(),
                }
            )
            Path(argv[argv.index("--output") + 1]).write_text(json.dumps(result))

        with (
            patch.object(validate_change.subprocess, "check_output", side_effect=protected_read),
            patch.object(validate_change.subprocess, "run", side_effect=protected_execution),
        ):
            result = validate_change.classify(bound, self.directory / "plan.json")
        validate_component_plan(json.loads(json.dumps(result)), json.loads(policy))
        self.assertEqual(result["component_plan"]["components"], ["python-example"])
        value = result["component_plan_provenance"]
        self.assertTrue(all((value[key] == expected for key, expected in bound.items())))
        self.assertEqual(value["policy_sha256"], hashlib.sha256(policy).hexdigest())
        self.assertEqual(value["classifier_sha256"], hashlib.sha256(source).hexdigest())
        self.assertFalse((self.directory / "output").exists())

    def test_complete_group_diff_uses_protected_main_not_event_parent(self):
        base, head, ancestor = ("a" * 40, "b" * 40, "c" * 40)
        raw = (
            b":100644 100644 1234567 2345678 M\0examples/minimal-rp/app.py\0"
            b":100644 100644 3456789 4567890 M\0infra/tofu/perf-aws-ec2/main.tf\0"
        )
        with patch("pr_plan.git", side_effect=[ancestor.encode(), raw]) as git:
            result = build_plan(ROOT, base, head, POLICY)
        self.assertEqual(git.call_args_list[0].args, (ROOT, "merge-base", base, head))
        self.assertEqual(
            git.call_args_list[1].args,
            (ROOT, "diff", "--raw", "-z", "--no-renames", "--no-ext-diff", ancestor, head, "--"),
        )
        self.assertEqual(
            result["component_plan"]["components"], ["infrastructure", "python-example"]
        )
        validate_component_plan(result, POLICY)

    def test_published_component_plan_and_provenance_remain_separate(self):
        bound = {"base": test_merge_queue.BASE, "source_head": test_merge_queue.HEAD}
        classified = plan(change("examples/minimal-rp/app.py"))
        classified["component_plan_provenance"] = {**bound, "classifier_sha256": "1" * 64}
        case = test_merge_queue.RunTests()
        case.setUp()
        try:
            with (
                patch.object(validate_change, "git", side_effect=test_merge_queue.graph),
                patch.object(validate_change, "classify", return_value=classified),
                patch.object(validate_change, "verify_signatures", return_value=[]),
            ):
                validate_change.run(bootstrap=False)
            recorded = json.loads(Path("ci-plan.json").read_text())
            validate_component_plan(recorded, POLICY)
            outputs = dict(line.split("=", 1) for line in case.output.read_text().splitlines())
            component = json.loads(outputs["component_targets"])
            provenance = json.loads(outputs["component_plan_provenance"])
            self.assertEqual(
                component,
                {
                    key: recorded["component_plan"][key]
                    for key in ("version", "components", "infrastructure_modules", "fallback")
                },
            )
            self.assertEqual(
                outputs["component_plan_sha256"],
                hashlib.sha256(Path("ci-plan.json").read_bytes()).hexdigest(),
            )
            self.assertNotIn("component_plan", outputs)
            self.assertEqual(provenance, recorded["component_plan_provenance"])
            self.assertEqual(provenance, classified["component_plan_provenance"])
        finally:
            case.doCleanups()

    def test_large_complete_plan_has_compact_outputs_bound_to_retained_file(self):
        bound = {"base": test_merge_queue.BASE, "source_head": test_merge_queue.HEAD}
        classified = plan(*(change(f"crates/server/src/shared_{i:04d}.rs") for i in range(3000)))
        classified["component_plan_provenance"] = {**bound, "classifier_sha256": "1" * 64}
        case = test_merge_queue.RunTests()
        case.setUp()
        try:
            with (
                patch.object(validate_change, "git", side_effect=test_merge_queue.graph),
                patch.object(validate_change, "classify", return_value=classified),
                patch.object(validate_change, "verify_signatures", return_value=[]),
            ):
                validate_change.run(bootstrap=False)
            raw = Path("ci-plan.json").read_bytes()
            recorded = json.loads(raw)
            validate_component_plan(recorded, POLICY)
            self.assertEqual(len(recorded["component_plan"]["changes"]), 3000)
            outputs_raw = case.output.read_text()
            self.assertLess(len(outputs_raw.encode("utf-16-le")), 8192)
            outputs = dict(line.split("=", 1) for line in outputs_raw.splitlines())
            self.assertNotIn("component_plan", outputs)
            self.assertNotIn("changes", json.loads(outputs["component_targets"]))
            self.assertEqual(outputs["component_plan_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(
                json.loads(outputs["component_targets"]),
                {
                    key: recorded["component_plan"][key]
                    for key in ("version", "components", "infrastructure_modules", "fallback")
                },
            )
            self.assertEqual(
                json.loads(outputs["component_plan_provenance"]),
                classified["component_plan_provenance"],
            )
        finally:
            case.doCleanups()

    def test_malformed_status_mode_combinations_select_all(self):
        for status, old, new in [
            ("A", "100644", "100644"),
            ("A", "100644", "000000"),
            ("D", "100644", "100644"),
            ("D", "000000", "100644"),
            ("M", "000000", "100644"),
            ("M", "100644", "000000"),
            ("T", "100644", "100644"),
            ("T", "100755", "100755"),
            ("T", "000000", "100644"),
        ]:
            with self.subTest(status=status, old=old, new=new):
                result = plan(change("examples/minimal-rp/app.py", status, old, new))
                self.assertEqual(result["scope"], "full")
                self.assertEqual(result["component_plan"]["components"], list(COMPONENTS))
                self.assertEqual(
                    result["component_plan"]["infrastructure_modules"], list(INFRASTRUCTURE_MODULES)
                )

    def test_valid_regular_status_mode_combinations_keep_registered_component(self):
        for status, old, new in [
            ("A", "000000", "100644"),
            ("D", "100644", "000000"),
            ("M", "100644", "100644"),
        ]:
            with self.subTest(status=status, old=old, new=new):
                result = plan(change("examples/minimal-rp/app.py", status, old, new))
                self.assertEqual(result["component_plan"]["components"], ["python-example"])
                self.assertEqual(result["component_plan"]["infrastructure_modules"], [])
