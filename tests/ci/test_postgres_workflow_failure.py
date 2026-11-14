"""Exercise the live PostgreSQL step's failure/status boundary in real Bash."""

# ruff: noqa: PT009, S603, S607 - unittest and fixed local workflow/tool argv
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "tests/organizations/check_current_runtime_postgres.py",
    "tests/organizations/current_runtime.py",
    "tests/organizations/current_process.py",
    "tests/organizations/current_postgres.py",
    "scripts/validation/database_execution.py",
    "scripts/validation/database_test_package.py",
    "scripts/validation/jose_server_test_package.py",
)
NIX_SHIM = """import os
from pathlib import Path

Path('checker-started').write_text('started')
if os.environ['CHECKER_MUTATE_SOURCE'] == '1':
    Path('tests/organizations/current_runtime.py').write_text('changed during checker')
raise SystemExit(int(os.environ['CHECKER_STATUS']))
"""


class PostgresWorkflowFailureTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name in SOURCES:
            target = self.directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        (self.directory / "artifacts/database-supplier-lifecycle").mkdir(parents=True)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        nix = self.bin / "nix"
        nix.write_text(f"#!{sys.executable}\n{NIX_SHIM}")
        nix.chmod(0o755)
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        matches = [
            step
            for job in workflow["jobs"].values()
            for step in job.get("steps", [])
            if step.get("name") == "Validate real PostgreSQL cleanup on this runner"
        ]
        self.assertEqual(len(matches), 1)
        self.assertFalse(matches[0].get("continue-on-error", False))
        self.step = matches[0]["run"]

    def run_step(self, status, *, mutate=False):
        environment = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_WORKSPACE": str(self.directory),
            "CHECKER_STATUS": str(status),
            "CHECKER_MUTATE_SOURCE": str(int(mutate)),
        }
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            environment.pop(name, None)
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", self.step],
            cwd=self.directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_post_execution_hash_check_and_original_failure_status(self):
        for status in (0, 37):
            for mutate in (False, True):
                with self.subTest(status=status, mutate=mutate):
                    shutil.copyfile(ROOT / SOURCES[1], self.directory / SOURCES[1])
                    result = self.run_step(status, mutate=mutate)
                    self.assertEqual(result.returncode, status or int(mutate), result.stderr)
                    self.assertIn(SOURCES[1] + (": FAILED" if mutate else ": OK"), result.stdout)
                    self.assertTrue((self.directory / "checker-started").is_file())

    def test_manifest_failure_prevents_checker_start(self):
        (self.directory / SOURCES[1]).unlink()
        result = self.run_step(0)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / "checker-started").exists())


if __name__ == "__main__":
    unittest.main()
