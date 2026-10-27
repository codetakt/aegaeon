"""Workflow discovery must be complete and must propagate linter failures."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class WorkflowLintTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.workflows = self.root / ".github/workflows"
        self.workflows.mkdir(parents=True)
        self.record = self.root / "arguments.json"
        tool = self.root / "actionlint"
        tool.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['LINT_RECORD']).write_text(json.dumps(sys.argv[1:]))\n"
            "sys.exit(int(os.environ.get('LINT_STATUS', '0')))\n"
        )
        tool.chmod(0o755)

    def invoke(self, status="0"):
        return subprocess.run(  # noqa: S603 - fixed script and isolated fixture
            ["bash", str(ROOT / "scripts/flake/lint_workflows.sh")],  # noqa: S607
            cwd=self.root,
            env={
                **os.environ,
                "PATH": f"{self.root}:{os.environ['PATH']}",
                "LINT_RECORD": str(self.record),
                "LINT_STATUS": status,
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def test_all_yaml_files_reach_linter_including_new_nested_files(self):
        for name in ("first.yml", "second.yaml", "nested/a workflow.yml", "README.md"):
            path = self.workflows / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        result = self.invoke()
        assert result.returncode == 0, result.stderr
        assert json.loads(self.record.read_text()) == [
            ".github/workflows/first.yml",
            ".github/workflows/nested/a workflow.yml",
            ".github/workflows/second.yaml",
        ]

    def test_missing_or_empty_workflow_tree_rejects_before_linter(self):
        assert self.invoke().returncode != 0
        self.workflows.rmdir()
        assert self.invoke().returncode != 0
        assert not self.record.exists()

    def test_linter_failure_is_preserved(self):
        (self.workflows / "invalid.yml").write_text("invalid\n")
        assert self.invoke("7").returncode == 7
        assert json.loads(self.record.read_text()) == [".github/workflows/invalid.yml"]
