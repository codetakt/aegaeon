# ruff: noqa: S603, S607 - fixed tools and generated hooks in isolated file fixtures
"""The actual TypeScript hook must run for its configuration and source inputs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUTS = (
    "eslint.config.cjs",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "scripts/check-strict-types.ts",
    "scripts/check-workflow-inventory.ts",
    "scripts/sdk/check_sdk_strict_types.ts",
    "scripts/sdk/tools-src/check-strict-types.ts",
    "tests/verified_core_wasm/root_strict_types_policy_test.ts",
    "tests/verified_core_wasm/strict_types_policy_test.ts",
    "tests/verified_core_wasm/workflow_inventory_policy_test.ts",
)


class TypeScriptHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        system = subprocess.check_output(
            ["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"],
            cwd=ROOT,
            text=True,
            timeout=120,
        ).strip()
        config = f".#checks.{system}.pre-commit-check.config"
        cls.config = json.loads(
            subprocess.check_output(
                ["nix", "eval", "--json", f"{config}.rawConfig"],
                cwd=ROOT,
                text=True,
                timeout=120,
            )
        )
        outputs = subprocess.check_output(
            [
                "nix",
                "build",
                "--no-link",
                "--print-out-paths",
                f"{config}.hooks.ts-lint.entry",
                f"{config}.package",
            ],
            cwd=ROOT,
            text=True,
            timeout=120,
        ).splitlines()
        assert len(outputs) == 2, outputs
        cls.pre_commit = str(Path(outputs[1]) / "bin/pre-commit")

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True, timeout=30)
        self.config_path = self.root / ".pre-commit-config.yaml"
        self.config_path.write_text(json.dumps(self.config))
        self.record = self.root / "npm-arguments.json"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        npm = self.bin / "npm"
        npm.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['NPM_RECORD']).write_text(json.dumps(sys.argv[1:]))\n"
            "sys.exit(int(os.environ['NPM_STATUS']))\n"
        )
        npm.chmod(0o755)
        (self.root / "node_modules").mkdir()

    def invoke(self, relative, status="0"):
        self.record.unlink(missing_ok=True)
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n")
        environment = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "PRE_COMMIT_HOME": str(self.root / "pre-commit-cache"),
            "NPM_RECORD": str(self.record),
            "NPM_STATUS": status,
        }
        for key in ("SKIP", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            environment.pop(key, None)
        return subprocess.run(
            [
                self.pre_commit,
                "run",
                "ts-lint",
                "--config",
                str(self.config_path),
                "--files",
                relative,
                "--verbose",
            ],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def test_config_only_change_runs_lint(self):
        result = self.invoke("eslint.config.cjs")
        assert result.returncode == 0, result.stdout + result.stderr
        assert self.record.exists(), result.stdout + result.stderr
        assert json.loads(self.record.read_text()) == ["run", "lint:ts"]

    def test_config_only_lint_failure_is_preserved(self):
        result = self.invoke("eslint.config.cjs", "17")
        assert result.returncode != 0, result.stdout + result.stderr
        assert "exit code: 17" in result.stdout
        assert json.loads(self.record.read_text()) == ["run", "lint:ts"]

    def test_existing_package_config_and_seven_sources_still_run_lint(self):
        for relative in INPUTS[1:]:
            with self.subTest(relative=relative):
                result = self.invoke(relative)
                assert result.returncode == 0, result.stdout + result.stderr
                assert self.record.exists(), result.stdout + result.stderr
                assert json.loads(self.record.read_text()) == ["run", "lint:ts"]

    def test_unrelated_and_obsolete_config_names_do_not_run_lint(self):
        for relative in ("README.md", "eslint.config.js", "nested/eslint.config.cjs"):
            with self.subTest(relative=relative):
                result = self.invoke(relative)
                assert result.returncode == 0, result.stdout + result.stderr
                assert not self.record.exists()
                assert "no files to check" in result.stdout

    def test_missing_node_modules_retains_explicit_local_skip(self):
        (self.root / "node_modules").rmdir()
        result = self.invoke("eslint.config.cjs")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Skipping ts-lint: run 'npm ci' first." in result.stdout
        assert not self.record.exists()
