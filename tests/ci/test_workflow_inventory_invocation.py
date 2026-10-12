# ruff: noqa: PT009, S603, S607 - unittest and fixed repository/tool argv
"""Run the inventory workflow steps against the checkout and changed file fixtures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECKER = "scripts/check-workflow-inventory.ts"
SELF_TEST = "tests/verified_core_wasm/workflow_inventory_policy_test.ts"
POLICY = "spec/workflow-inventory.current.json"
INVENTORY_STEPS = (
    ("ci.yml", "ci", "Workflow inventory audit"),
    ("lint.yml", "lint", "Run workflow inventory audit"),
)
NIX_SHIM = """import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if args[:5] != ["develop", ".#ci", "--command", "node", "--experimental-strip-types"]:
    raise SystemExit("unexpected inventory Nix invocation")
with Path(os.environ["INVENTORY_COMMANDS"]).open("a") as output:
    output.write(json.dumps(args) + "\\n")
node = os.environ["INVENTORY_NODE"]
os.execv(node, [node, *args[4:]])
"""


class WorkflowInventoryInvocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Docs owns discovery but has no Node package. Resolve the repository's
        # lightweight pinned Node shell once, then execute the real checker.
        result = subprocess.run(
            ["nix", "develop", ".#typescript", "--command", "node", "--print", "process.execPath"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        cls.node = result.stdout.strip()
        if not Path(cls.node).is_file():
            raise RuntimeError(result.stdout + result.stderr)

    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.fixture = self.directory / "checkout"
        shutil.copytree(ROOT / ".github/workflows", self.fixture / ".github/workflows")
        for name in (CHECKER, SELF_TEST, POLICY):
            destination = self.fixture / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        nix = self.bin / "nix"
        nix.write_text(f"#!{sys.executable}\n{NIX_SHIM}")
        nix.chmod(0o755)
        self.trace = self.directory / "commands.jsonl"
        self.required = json.loads((ROOT / POLICY).read_text())["required_workflows"]
        self.steps = {}
        for filename, job, name in INVENTORY_STEPS:
            workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
            matches = [step for step in workflow["jobs"][job]["steps"] if step.get("name") == name]
            self.assertEqual(len(matches), 1)
            self.assertFalse(matches[0].get("continue-on-error", False))
            self.steps[filename] = matches[0]["run"]

    def run_step(self, script, checkout):
        self.trace.unlink(missing_ok=True)
        environment = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "INVENTORY_COMMANDS": str(self.trace),
            "INVENTORY_NODE": self.node,
            "TMPDIR": str(self.directory),
        }
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "NODE_OPTIONS"):
            environment.pop(name, None)
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
            cwd=checkout,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        commands = (
            [json.loads(line) for line in self.trace.read_text().splitlines()]
            if self.trace.exists()
            else []
        )
        return result, commands

    def check_success(self, checkout):
        for filename, script in self.steps.items():
            with self.subTest(workflow=filename):
                result, commands = self.run_step(script, checkout)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("[workflow-inventory]", result.stdout)
                self.assertIn("root workflow inventory policy tests passed", result.stdout)
                self.assertEqual(
                    commands,
                    [
                        ["develop", ".#ci", "--command", "node", "--experimental-strip-types", name]
                        for name in (CHECKER, SELF_TEST)
                    ],
                )

    def check_failure(self, message):
        for filename, script in self.steps.items():
            with self.subTest(workflow=filename):
                result, commands = self.run_step(script, self.fixture)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertEqual(len(commands), 1)
                self.assertEqual(commands[0][-1], CHECKER)
                self.assertNotIn("root workflow inventory policy tests passed", result.stdout)

    def test_both_workflow_steps_check_the_real_checkout_and_retain_self_test(self):
        self.check_success(ROOT)

    def test_every_required_workflow_removal_fails_both_actual_steps(self):
        for required in self.required:
            with self.subTest(removed=required["path"]):
                path = self.fixture / required["path"]
                original = path.read_bytes()
                path.unlink()
                self.check_failure(f"{required['path']}: missing workflow file")
                path.write_bytes(original)

    def test_changed_required_name_fails_before_the_self_test(self):
        path = self.fixture / self.required[0]["path"]
        path.write_text("name: Wrong Name\n")
        self.check_failure("expected workflow name")

    def test_malformed_policy_fails_both_actual_steps(self):
        for policy in ("{", '{"required_workflows": null}'):
            with self.subTest(policy=policy):
                (self.fixture / POLICY).write_text(policy)
                self.check_failure("JSON" if policy == "{" else "requires `required_workflows`")

    def test_non_file_workflow_input_fails_both_actual_steps(self):
        path = self.fixture / self.required[0]["path"]
        path.unlink()
        path.mkdir()
        self.check_failure("EISDIR")

    def test_additional_unrelated_workflow_remains_allowed(self):
        (self.fixture / ".github/workflows/extra.yml").write_text("name: Additional Workflow\n")
        self.check_success(self.fixture)


if __name__ == "__main__":
    unittest.main()
