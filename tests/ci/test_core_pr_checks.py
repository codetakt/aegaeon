"""Check ownership must preserve every check and fail before unsafe delegation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))

from run_core_pr_checks import FORMAL_PACKAGES, partition  # noqa: E402 - standalone Nix tests


def drv(name):
    return "/nix/store/" + "a" * 32 + f"-{name}.drv"


class CoreCheckTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.formal = {name: drv(name) for name in FORMAL_PACKAGES}
        self.checks = {**self.formal, "tests": drv("tests"), "future-check": drv("future")}
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
    sys.exit(int(os.environ.get("FAKE_FLAKE_EXIT", "0")))
if args[0] == "eval":
    if os.environ.get("FAKE_INVALID_JSON"):
        print("invalid"); sys.exit(0)
    print(json.dumps(data["checks" if "checks." in args[2] else "packages"]))
    sys.exit(int(os.environ.get("FAKE_EVAL_EXIT", "0")))
if args[0] == "build":
    sys.exit(int(os.environ.get("FAKE_BUILD_EXIT", "0")))
sys.exit(2)
"""
        )
        executable.chmod(0o755)

    def write_inventory(self):
        (self.root / "inventory.json").write_text(
            json.dumps({"checks": self.checks, "packages": self.formal})
        )

    def invoke(self, **environment):
        return subprocess.run(  # noqa: S603 - controlled tool and fixture paths
            [sys.executable, str(ROOT / "scripts/ci/run_core_pr_checks.py")],
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
        result = self.invoke()
        assert result.returncode == 0, result.stderr
        commands = self.commands()
        assert commands[0] == ["flake", "check", "--no-build", "--print-build-logs"]
        builds = [command for command in commands if command[0] == "build"]
        assert len(builds) == 1
        assert set(builds[0][3:]) == {drv("tests") + "^*", drv("future") + "^*"}
        owners = json.loads((self.root / "artifacts/ci-check-ownership.json").read_text())["owners"]
        assert set(owners["core"]) | set(owners["verification"]) == set(self.checks)
        assert not set(owners["core"]) & set(owners["verification"])
        assert owners["verification"] == self.formal

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
        full = next(step for step in steps if step.get("name") == "nix flake check")
        assert full["if"] == "${{ !inputs.delegate-formal-checks }}"
        assert "nix flake check --print-build-logs" in full["run"]
