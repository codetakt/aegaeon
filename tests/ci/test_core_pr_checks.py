"""Check ownership must preserve every check and fail before unsafe delegation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))

from run_core_pr_checks import (  # noqa: E402 - standalone Nix tests
    DATABASE_CONSUMERS,
    FORMAL_PACKAGES,
    build_checks,
    partition,
)


def drv(name):
    return "/nix/store/" + "a" * 32 + f"-{name}.drv"


class CoreCheckTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.formal = {name: drv(name) for name in FORMAL_PACKAGES}
        self.functional = {name: drv(name) for name in ("verifyDudect", "verified-reqs")}
        self.checks = {
            **self.formal,
            **self.functional,
            "tests": drv("tests"),
            "future-check": drv("future"),
        }
        self.prerequisites = {
            "server-distribution": drv("distribution"),
            "database-tests": drv("database-package"),
        }
        self.write_inventory()
        executable = self.root / "nix"
        executable.write_text(
            f"#!{sys.executable}\n"
            """import json, os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path("commands.jsonl").open("a") as out:
    out.write(json.dumps(args) + "\\n")
data = json.loads(pathlib.Path("inventory.json").read_text())
if args[0] == "flake":
    if os.environ.get("FAKE_COLD_IFD") and not pathlib.Path("ifd-prepared").exists():
        sys.exit(24)
    sys.exit(int(os.environ.get("FAKE_FLAKE_EXIT", "0")))
if args[0] == "eval":
    if os.environ.get("FAKE_INVALID_JSON"):
        print("invalid"); sys.exit(0)
    field = "checks" if "checks." in args[2] else "packages"
    if "server-distribution" in args[-1]: field = "prerequisites"
    print(json.dumps(data[field]))
    if "checks." in args[2]:
        pathlib.Path("ifd-prepared").touch()
    sys.exit(int(os.environ.get("FAKE_EVAL_EXIT", "0")))
if args[:2] == ["derivation", "show"]:
    print(json.dumps(data["graph"]))
    sys.exit(int(os.environ.get("FAKE_GRAPH_EXIT", "0")))
if args[0] == "build":
    if os.environ.get("FAKE_FAILED_TARGET", "not-a-target") in args:
        sys.exit(23)
    if any(target in args for target in json.loads(os.environ.get("FAKE_FAILED_TARGETS", "[]"))):
        sys.exit(23)
    sys.exit(int(os.environ.get("FAKE_BUILD_EXIT", "0")))
if args[:2] == ["--query", "--outputs"]:
    print(os.environ.get("FAKE_BAD_OUTPUT") or args[2].removesuffix(".drv"))
    sys.exit(0)
sys.exit(2)
"""
        )
        executable.chmod(0o755)
        (self.root / "nix-store").symlink_to(executable)

    def write_inventory(self):
        nodes = {
            Path(path).name: {"version": 4, "outputs": {"out": {}}, "inputs": {"drvs": {}}}
            for path in {*self.checks.values(), *self.formal.values(), *self.prerequisites.values()}
        }
        for name in DATABASE_CONSUMERS & self.checks.keys():
            dependencies = [self.prerequisites["database-tests"]]
            if name != "lti-browser-consent":
                dependencies.append(self.prerequisites["server-distribution"])
            nodes[Path(self.checks[name]).name]["inputs"]["drvs"] = {
                Path(dependency).name: {"outputs": ["out"], "dynamicOutputs": {}}
                for dependency in dependencies
            }
        (self.root / "inventory.json").write_text(
            json.dumps(
                {
                    "checks": self.checks,
                    "packages": self.formal,
                    "prerequisites": self.prerequisites,
                    "graph": {"version": 4, "derivations": nodes},
                }
            )
        )

    def invoke(self, *arguments, **environment):
        return subprocess.run(  # noqa: S603 - controlled tool and fixture paths
            [sys.executable, str(ROOT / "scripts/ci/run_core_pr_checks.py"), *arguments],
            cwd=self.root,
            env={
                **os.environ,
                "PATH": f"{self.root}:{os.environ['PATH']}",
                "GITHUB_EVENT_NAME": "pull_request",
                **environment,
            },
            text=True,
            capture_output=True,
            check=False,
        )

    def commands(self):
        path = self.root / "commands.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_full_evaluation_and_unknown_checks_are_preserved(self):
        self.checks["functional-alias"] = self.functional["verifyDudect"]
        self.write_inventory()
        result = self.invoke()
        assert result.returncode == 0, result.stderr
        commands = self.commands()
        assert [c[0] for c in commands] == ["eval", "eval", "flake", "build"]
        assert commands[2] == ["flake", "check", "--no-build", "--print-build-logs"]
        builds = [c for c in commands if c[0] == "build"]
        assert len(builds) == 1
        assert builds[0][:7] == [
            "build",
            "--no-link",
            "--print-build-logs",
            "--max-jobs",
            "1",
            "--cores",
            "2",
        ]
        expected = set(self.checks.values()) - set(self.formal.values())
        assert set(builds[0][7:]) == {d + "^*" for d in expected}
        owners = json.loads((self.root / "artifacts/ci-check-ownership.json").read_text())["owners"]
        assert set(owners["core"]) | set(owners["verification"]) == set(self.checks)
        assert not set(owners["core"]) & set(owners["verification"])
        assert owners["verification"] == self.formal
        assert not (self.root / "artifacts/ci-dudect-outputs.json").exists()

    def test_cold_ifd_inputs_are_prepared_without_building_delegated_checks(self):
        result = self.invoke(FAKE_COLD_IFD="1")
        assert result.returncode == 0, result.stderr
        builds = [c for c in self.commands() if c[0] == "build"]
        assert len(builds) == 1
        assert not {d + "^*" for d in self.formal.values()} & set(builds[0][7:])

    def test_full_output_validation_failure_still_stops_before_receipt_and_build(self):
        result = self.invoke(FAKE_COLD_IFD="1", FAKE_FLAKE_EXIT="25")
        assert result.returncode != 0
        assert not any(c[0] == "build" for c in self.commands())
        assert not (self.root / "artifacts/ci-check-ownership.json").exists()

    def test_push_and_manual_runs_keep_every_formal_and_functional_check(self):
        self.checks.update({name: drv(name) for name in DATABASE_CONSUMERS})
        self.write_inventory()
        for event in ("push", "workflow_dispatch"):
            before = len(self.commands())
            result = self.invoke("--all-checks", GITHUB_EVENT_NAME=event)
            assert result.returncode == 0, result.stderr
            builds = [c for c in self.commands()[before:] if c[0] == "build"]
            assert [c[0] for c in self.commands()[before:]] == ["eval", "eval", "flake", "build"]
            assert len(builds) == 1
            assert builds[0][3:7] == ["--max-jobs", "1", "--cores", "2"]
            assert set(builds[0][7:]) == {d + "^*" for d in self.checks.values()}

    def test_database_consumers_and_their_aliases_run_last_without_omission(self):
        self.checks.update({name: drv(name) for name in DATABASE_CONSUMERS})
        self.checks["future-database-alias"] = self.checks["lti-packaged-runtime"]
        self.checks["functional-alias"] = self.functional["verifyDudect"]
        self.write_inventory()
        result = self.invoke(GITHUB_EVENT_NAME="merge_group")
        assert result.returncode == 0, result.stderr
        builds = [command for command in self.commands() if command[0] == "build"]
        assert len(builds) == 3
        deferred = {self.checks[name] + "^*" for name in DATABASE_CONSUMERS}
        assert not deferred & set(builds[0][7:])
        assert builds[1][7:] == [self.prerequisites["server-distribution"] + "^*"]
        assert set(builds[2][7:]) == deferred
        targets = [target for command in builds for target in command[7:]]
        expected = (set(self.checks.values()) - set(self.formal.values())) | {
            self.prerequisites["server-distribution"]
        }
        assert len(targets) == len(set(targets)) == len(expected)
        assert set(targets) == {target + "^*" for target in expected}
        assert all(command[3:7] == ["--max-jobs", "1", "--cores", "2"] for command in builds)
        record = json.loads((self.root / "artifacts/ci-check-ownership.json").read_text())
        phases = record["build_phases"]
        names = [name for phase in phases for name in phase]
        assert len(names) == len(set(names)) == len(record["owners"]["core"])
        assert {name: value for phase in phases for name, value in phase.items()} == record[
            "owners"
        ]["core"]
        assert "future-database-alias" in phases[1]
        assert record["prerequisite"]["before_phase"] == 1
        assert record["prerequisite"]["required_by"] == [
            "future-database-alias",
            "lti-packaged-runtime",
            "organizations-production-runtime",
        ]

    def test_failure_in_either_phase_fails_without_retry_or_later_execution(self):
        self.checks["lti-packaged-runtime"] = drv("database-consumer")
        self.write_inventory()
        for target, expected_builds in (
            (self.functional["verifyDudect"], 1),
            (self.prerequisites["server-distribution"], 2),
            (self.checks["lti-packaged-runtime"], 3),
        ):
            with self.subTest(target=target):
                before = len(self.commands())
                result = self.invoke(FAKE_FAILED_TARGET=target + "^*")
                assert result.returncode != 0
                builds = [c for c in self.commands()[before:] if c[0] == "build"]
                assert len(builds) == expected_builds
                assert sum(target + "^*" in command for command in builds) == 1

    def test_only_deferred_aliases_never_issue_an_empty_default_build(self):
        self.checks = {
            **self.formal,
            "lti-packaged-runtime": drv("database-consumer"),
            "future-alias": drv("database-consumer"),
        }
        self.write_inventory()
        result = self.invoke()
        assert result.returncode == 0, result.stderr
        builds = [command for command in self.commands() if command[0] == "build"]
        assert len(builds) == 2
        assert builds[0][7:] == [self.prerequisites["server-distribution"] + "^*"]
        assert builds[1][7:] == [drv("database-consumer") + "^*"]

    def test_future_source_cannot_request_an_unnecessary_prerequisite(self):
        self.checks["lti-packaged-runtime"] = drv("consumer")
        for condition in (
            "not-required",
            "already-early",
            "extra-output",
            "database-input",
            "formal-input",
        ):
            with self.subTest(condition=condition):
                self.write_inventory()
                path = self.root / "inventory.json"
                data = json.loads(path.read_text())
                nodes = data["graph"]["derivations"]
                distribution = Path(self.prerequisites["server-distribution"]).name
                edge = {"outputs": ["out"], "dynamicOutputs": {}}
                if condition == "not-required":
                    del nodes[Path(self.checks["lti-packaged-runtime"]).name]["inputs"]["drvs"][
                        distribution
                    ]
                elif condition == "already-early":
                    nodes[Path(self.checks["tests"]).name]["inputs"]["drvs"][distribution] = edge
                elif condition == "extra-output":
                    nodes[distribution]["outputs"]["unused"] = {}
                else:
                    target = (
                        self.prerequisites["database-tests"]
                        if condition == "database-input"
                        else self.formal["verifyKani"]
                    )
                    nodes[distribution]["inputs"]["drvs"][Path(target).name] = edge
                path.write_text(json.dumps(data))
                before = len(self.commands())
                result = self.invoke()
                assert result.returncode == 0, result.stderr
                builds = [c for c in self.commands()[before:] if c[0] == "build"]
                assert len(builds) == 2
                assert not any(
                    self.prerequisites["server-distribution"] + "^*" in c for c in builds
                )
                receipt = json.loads((self.root / "artifacts/ci-check-ownership.json").read_text())
                assert receipt["prerequisite"]["derivations"] == {}

    def test_prerequisite_alias_of_existing_check_is_never_requested_twice(self):
        self.checks["lti-packaged-runtime"] = drv("consumer")
        self.checks["distribution-alias"] = self.prerequisites["server-distribution"]
        self.write_inventory()
        result = self.invoke()
        assert result.returncode == 0, result.stderr
        builds = [c for c in self.commands() if c[0] == "build"]
        assert len(builds) == 2
        assert sum(self.prerequisites["server-distribution"] + "^*" in c for c in builds) == 1

    def test_unknown_or_incomplete_graph_refuses_before_any_build(self):
        self.checks["lti-packaged-runtime"] = drv("consumer")
        for condition in ("version", "missing-input", "missing-root", "dynamic", "output"):
            with self.subTest(condition=condition):
                self.write_inventory()
                path = self.root / "inventory.json"
                data = json.loads(path.read_text())
                graph = data["graph"]
                distribution = Path(self.prerequisites["server-distribution"]).name
                node = graph["derivations"][Path(self.checks["lti-packaged-runtime"]).name]
                if condition == "version":
                    graph["version"] = 5
                elif condition == "missing-input":
                    del graph["derivations"][distribution]
                elif condition == "missing-root":
                    del graph["derivations"][Path(self.checks["tests"]).name]
                elif condition == "dynamic":
                    node["inputs"]["drvs"][distribution]["dynamicOutputs"] = {"unknown": {}}
                else:
                    node["inputs"]["drvs"][distribution]["outputs"] = ["not-a-real-output"]
                path.write_text(json.dumps(data))
                before = len(self.commands())
                assert self.invoke().returncode != 0
                assert not any(c[0] == "build" for c in self.commands()[before:])

    def test_failed_build_is_not_retried_or_converted_to_success(self):
        result = self.invoke(FAKE_FAILED_TARGET=self.functional["verifyDudect"] + "^*")
        assert result.returncode != 0
        assert len([c for c in self.commands() if c[0] == "build"]) == 1

    def test_empty_inventory_and_spawn_failure_are_rejected(self):
        with pytest.raises(ValueError, match="No core checks"):
            build_checks({})
        with (
            patch("build_observations.subprocess.Popen", side_effect=OSError("cannot spawn")),
            pytest.raises(OSError, match="cannot spawn"),
        ):
            build_checks(self.functional)

    def test_merge_group_uses_the_same_complete_check_inventory(self):
        result = self.invoke(GITHUB_EVENT_NAME="merge_group")
        assert result.returncode == 0, result.stderr
        assert any(command[0] == "build" for command in self.commands())

    def test_missing_delegated_check_fails_before_build(self):
        del self.checks["verifyKani"]
        self.write_inventory()
        assert self.invoke().returncode != 0
        assert not any(command[0] == "build" for command in self.commands())

    def test_divergent_package_or_duplicate_ownership_is_rejected(self):
        with pytest.raises(ValueError, match="do not build"):
            partition(self.checks, {**self.formal, "verifyKani": drv("other")})
        with pytest.raises(ValueError, match="both core"):
            partition({**self.checks, "alias": self.formal["verifyKani"]}, self.formal)
        with pytest.raises(ValueError, match="inventory"):
            partition(self.checks, {**self.formal, "unknown": drv("other")})

    def test_errors_propagate_and_non_pr_events_cannot_delegate(self):
        for variable in (
            "FAKE_FLAKE_EXIT",
            "FAKE_EVAL_EXIT",
            "FAKE_INVALID_JSON",
            "FAKE_BUILD_EXIT",
        ):
            with self.subTest(variable=variable):
                assert self.invoke(**{variable: "42"}).returncode != 0
        for event in ("push", "workflow_dispatch", ""):
            with self.subTest(event=event):
                before = self.commands()
                assert self.invoke(GITHUB_EVENT_NAME=event).returncode != 0
                assert self.commands() == before

    def test_malformed_derivation_is_rejected_before_build(self):
        self.checks["tests"] = str(self.root / "untrusted.drv")
        self.write_inventory()
        assert self.invoke().returncode != 0
        assert not any(command[0] == "build" for command in self.commands())

    def test_only_full_pr_caller_enables_delegation_and_keeps_both_owners_required(self):
        core = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        pr = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        # PyYAML's YAML 1.1 loader interprets the Actions key "on" as True.
        option = core[True]["workflow_call"]["inputs"]["delegate-formal-checks"]
        assert option["default"] is False
        assert option["type"] == "boolean"
        assert pr["jobs"]["core"]["with"]["delegate-formal-checks"] is True
        assert pr["jobs"]["core"]["if"] == pr["jobs"]["verification"]["if"]
        assert pr["jobs"]["core"]["if"] == "needs.plan.outputs.scope == 'full'"
        assert {"core", "verification"} <= set(pr["jobs"]["required"]["needs"])
        steps = core["jobs"]["ci"]["steps"]
        openapi = next(step for step in steps if step.get("name") == "Check OpenAPI artefact drift")
        assert "if" not in openapi
        assert "nix build .#openapi-check --no-link --print-build-logs" in openapi["run"]
        full = next(step for step in steps if step.get("id") == "core-checks")
        assert "if" not in full
        assert (
            full["env"]["DELEGATE_FORMAL_CHECKS"] == "${{ inputs.delegate-formal-checks || false }}"
        )
        assert 'if [ "$DELEGATE_FORMAL_CHECKS" = "true" ]; then' in full["run"]
        assert "python3 scripts/ci/run_core_pr_checks.py --all-checks" in full["run"]
        assert not any("collect_dudect_outputs" in step.get("run", "") for step in steps)
        assert not any("dudect-core-gates" in str(step.get("with", {})) for step in steps)
