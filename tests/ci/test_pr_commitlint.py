"""Exercise repository and generated PR workflows against real Git histories."""

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

# The stand-in observes the range given to commitlint and rejects sentinel
# messages. Commitlint's formatting rules are covered by the normal CI gate.
LINTER = """import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
if '--from' in args:
    start = args[args.index('--from') + 1]
    end = args[args.index('--to') + 1]
    commits = subprocess.check_output(
        ['git', 'rev-list', start + '..' + end], text=True).splitlines()
    messages = [subprocess.check_output(
        ['git', 'show', '-s', '--format=%s', c], text=True).strip()
        for c in commits]
    mode = 'range'
else:
    commits = []
    messages = [pathlib.Path(args[args.index('--edit') + 1]).read_text()]
    mode = 'edit'
pathlib.Path(os.environ['COMMITLINT_TEST_REPORT']).write_text(json.dumps({
    'mode': mode, 'commits': commits, 'messages': messages}))
sys.exit(1 if any(m.startswith('invalid ') for m in messages) else 0)
"""


class PullRequestCommitlintTests(unittest.TestCase):
    workflow = ROOT / ".github/workflows/lint.yml"
    nix_shell = ".#ci"

    def git(self, directory: Path, *args: str) -> str:
        return subprocess.check_output(  # noqa: S603 - fixed tool and fixture argv, no shell
            ["git", *args],  # noqa: S607 - Git from the pinned shell
            cwd=directory,
            text=True,
            stderr=subprocess.PIPE,
        ).strip()

    def configure(self, directory: Path) -> None:
        for key, value in [
            ("user.name", "Fixture Author"),
            ("user.email", "fixture@example.invalid"),
            ("commit.gpgsign", "false"),
            ("core.hooksPath", "/dev/null"),
        ]:
            self.git(directory, "config", key, value)

    def commit(self, directory: Path, message: str) -> str:
        self.git(directory, "commit", "--allow-empty", "-m", message)
        return self.git(directory, "rev-parse", "HEAD")

    def create_history(self) -> Path:
        seed = self.root / "seed"
        seed.mkdir()
        self.git(seed, "init", "--initial-branch=main")
        self.configure(seed)
        self.commit(seed, "chore: initialize fixture")
        self.git(seed, "checkout", "-b", "topic")
        topic = self.commit(seed, "fix(ci): update a topic")
        self.git(seed, "checkout", "main")
        self.old_main = self.commit(seed, "invalid existing main message")
        self.git(seed, "checkout", "topic")
        self.git(seed, "merge", "--no-ff", "main", "-m", "Merge main into topic")
        first_merge = self.git(seed, "rev-parse", "HEAD")
        self.git(seed, "checkout", "main")
        self.base = self.commit(seed, "chore: advance main")
        self.git(seed, "checkout", "topic")
        self.git(seed, "merge", "--no-ff", "main", "-m", "Merge main into topic")
        self.head = self.git(seed, "rev-parse", "HEAD")
        self.expected = {topic, first_merge, self.head}
        return seed

    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        seed = self.create_history()
        self.origin = self.root / "origin.git"
        self.git(self.root, "clone", "--bare", str(seed), str(self.origin))
        self.repo = self.root / "checkout"
        self.git(
            self.root,
            "clone",
            "--no-local",
            "--branch",
            "topic",
            str(self.origin),
            str(self.repo),
        )
        self.configure(self.repo)
        scripts = self.repo / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "scripts/commitlint-range.sh", scripts)
        self.install_tools()
        self.report = self.root / "lint-report.json"

    def install_tools(self) -> None:
        self.bin = self.root / "bin"
        self.bin.mkdir()
        nix = self.bin / "nix"
        nix.write_text(
            '#!/bin/sh\nset -eu\n[ "$1" = develop ]\n'
            f'[ "$2" = {self.nix_shell} ]\n[ "$3" = --command ]\nshift 3\nexec "$@"\n'
        )
        nix.chmod(0o755)
        self.linter = self.bin / "commitlint"
        self.linter.write_text(f"#!{sys.executable}\n{LINTER}")
        self.linter.chmod(0o755)

    def run_step(self, overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        workflow = yaml.safe_load(self.workflow.read_text())
        step = next(
            s
            for job in workflow["jobs"].values()
            for s in job["steps"]
            if s.get("name") == "Lint commit messages (pull_request)"
        )
        revisions = {
            "${{ github.event.pull_request.base.sha }}": self.base,
            "${{ github.event.pull_request.head.sha }}": self.head,
        }
        env = os.environ.copy()
        env.update(
            PATH=str(self.bin) + os.pathsep + env["PATH"],
            COMMITLINT_BIN=str(self.linter),
            COMMITLINT_TEST_REPORT=str(self.report),
            COMMITLINT_BASELINE_FILE=str(self.root / "absent-baseline"),
        )
        for name, expression in step.get("env", {}).items():
            env[name] = revisions[expression]
        env.update(overrides or {})
        # Render the old workflow too, so the regression reproduces its real
        # shallow-fetch behavior before the fix instead of failing to parse.
        command = step["run"].replace("${{ github.base_ref }}", "main")
        return subprocess.run(  # noqa: S603 - repository workflow with fixture environment
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command],  # noqa: S607
            cwd=self.repo,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_merged_main_history_is_excluded(self) -> None:
        result = self.run_step()
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(self.report.read_text())
        assert report["mode"] == "range"
        assert set(report["commits"]) == self.expected
        assert self.old_main not in report["commits"]

    def test_base_moving_after_event_does_not_remove_pr_commits(self) -> None:
        self.git(self.origin, "update-ref", "refs/heads/main", self.head)
        result = self.run_step()
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(self.report.read_text())
        assert report["mode"] == "range"
        assert set(report["commits"]) == self.expected

    def test_invalid_pr_message_still_fails(self) -> None:
        self.head = self.commit(self.repo, "invalid new PR message")
        result = self.run_step()
        assert result.returncode != 0
        report = json.loads(self.report.read_text())
        assert self.head in report["commits"]
        assert self.old_main not in report["commits"]

    def test_missing_event_revision_stops_before_linter(self) -> None:
        for name in ["PR_BASE_SHA", "PR_HEAD_SHA"]:
            with self.subTest(name=name):
                self.report.unlink(missing_ok=True)
                result = self.run_step({name: ""})
                assert result.returncode != 0
                assert not self.report.exists()


class CorePullRequestCommitlintTests(PullRequestCommitlintTests):
    workflow = ROOT / ".github/workflows/ci.yml"


class ScaffoldPullRequestCommitlintTests(PullRequestCommitlintTests):
    nix_shell = "."

    @classmethod
    def setUpClass(cls) -> None:
        fixture = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        generated = fixture / "sdk"
        dist = fixture / "dist"
        dist.mkdir()
        # The scaffold copies these files; this suite only executes its workflow.
        # Placeholder artifact bytes provide no SDK or verification evidence.
        for name in [
            "manifest.json",
            "verified_core.wasm",
            "verified_core.abi.json",
            "verified_core.wasm.sha256",
            "verified_core.wasm.sha512",
            "verified_core.wasm.sri",
            "verified-core-sbom.json",
            "types.d.ts",
            "integrity.txt",
        ]:
            (dist / name).write_text("{}\n")
        result = subprocess.run(  # noqa: S603 - repository generator and fixture paths
            [  # noqa: S607 - Node from the pinned shell
                "node",
                "--experimental-strip-types",
                str(ROOT / "scripts/sdk/scaffold_sdk_repo_workspace.ts"),
                "--dist-dir",
                str(dist),
                "--out-dir",
                str(generated),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        cls.workflow = generated / ".github/workflows/lint.yml"


if __name__ == "__main__":
    unittest.main()
