"""Exercise the PR title policy with the pinned commitlint CLI."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LONG_TITLE = (
    "chore(deps): update flask requirement from <4,>=3.0 to >=3.1.3,<4 in /examples/minimal-rp"
)


class PullRequestTitleLintTests(unittest.TestCase):
    def lint(
        self, title: str, author: str | None, *, commit: bool = False, actor: str = "maintainer"
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop("PR_AUTHOR_LOGIN", None)
        env.update(PR_TITLE=title, GITHUB_ACTOR=actor)
        if author is not None:
            env["PR_AUTHOR_LOGIN"] = author
        command = (
            ["commitlint", "--config", "commitlint.config.cjs"]
            if commit
            else ["bash", "scripts/ci/lint_pr_title.sh"]
        )
        return subprocess.run(  # noqa: S603 - fixed CLI with metadata passed as data
            command,
            cwd=ROOT,
            env=env,
            input=title + "\n" if commit else None,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_dependabot_length_warns_even_when_a_human_runs_ci(self) -> None:
        for actor in ("dependabot[bot]", "maintainer"):
            with self.subTest(actor=actor):
                result = self.lint(LONG_TITLE, "dependabot[bot]", actor=actor)
                assert result.returncode == 0, result.stdout + result.stderr
                assert "header-max-length" in result.stdout
                assert "1 warnings" in result.stdout

    def test_other_and_missing_authors_keep_blocking_length(self) -> None:
        for author in (None, "", "maintainer", "dependabot", "dependabot[bot]-fake"):
            with self.subTest(author=author):
                result = self.lint(LONG_TITLE, author, actor="dependabot[bot]")
                assert result.returncode != 0
                assert "header-max-length" in result.stdout

    def test_length_boundary_and_short_titles(self) -> None:
        title = "chore(deps): " + "a" * 59
        assert len(title) == 72
        for author in ("maintainer", "dependabot[bot]"):
            with self.subTest(author=author):
                result = self.lint(title, author)
                assert result.returncode == 0, result.stdout + result.stderr
                assert "header-max-length" not in result.stdout
        result = self.lint(title + "a", "maintainer")
        assert result.returncode != 0
        assert "header-max-length" in result.stdout

    def test_other_title_rules_still_block_dependabot(self) -> None:
        for title, rule in (
            ("unknown(deps): update dependency", "type-enum"),
            ("chore(unknown): update dependency", "scope-enum"),
            ("chore(deps): update dependency.", "subject-full-stop"),
            ("update dependency", "type-empty"),
            (LONG_TITLE.replace("chore", "unknown", 1), "type-enum"),
        ):
            with self.subTest(title=title):
                result = self.lint(title, "dependabot[bot]")
                assert result.returncode != 0
                assert rule in result.stdout

    def test_empty_title_is_rejected(self) -> None:
        result = self.lint("", "dependabot[bot]")
        assert result.returncode != 0
        assert "Pull request title is required" in result.stderr

    def test_commit_headers_remain_blocking_for_dependabot(self) -> None:
        result = self.lint(LONG_TITLE, "dependabot[bot]", commit=True)
        assert result.returncode != 0
        assert "header-max-length" in result.stdout

    def test_title_is_passed_as_literal_data(self) -> None:
        result = self.lint("chore(deps): $(exit 99) `exit 98`", "dependabot[bot]")
        assert result.returncode == 0, result.stdout + result.stderr

    def test_all_repository_title_gates_use_pr_author_and_shared_helper(self) -> None:
        for workflow in ("ci", "lint"):
            with self.subTest(workflow=workflow):
                document = yaml.safe_load((ROOT / f".github/workflows/{workflow}.yml").read_text())
                steps = [step for job in document["jobs"].values() for step in job["steps"]]
                step = next(step for step in steps if step.get("name") == "Lint PR title")
                assert step["if"] == "github.event_name == 'pull_request'"
                assert (
                    step["env"]["PR_AUTHOR_LOGIN"] == "${{ github.event.pull_request.user.login }}"
                )
                assert step["env"]["PR_TITLE"] == "${{ github.event.pull_request.title }}"
                assert step["run"] == "nix develop .#ci --command bash scripts/ci/lint_pr_title.sh"
        parent = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        assert (
            parent["jobs"]["docs"]["with"]["pr-author"]
            == "${{ github.event.pull_request.user.login || '' }}"
        )
        docs = yaml.safe_load((ROOT / ".github/workflows/documentation.yml").read_text())
        inputs = docs[True]["workflow_call"]["inputs"]
        assert inputs["pr-author"] == {"required": False, "type": "string", "default": ""}
        step = next(step for step in docs["jobs"]["metadata"]["steps"] if "run" in step)
        assert step["env"]["PR_AUTHOR_LOGIN"] == "${{ inputs.pr-author }}"
        metadata = (ROOT / "scripts/ci/run_docs_metadata.sh").read_text()
        assert "if [[ $GITHUB_EVENT_NAME == pull_request ]]; then" in metadata
        assert "bash scripts/ci/lint_pr_title.sh" in metadata
        assert "commitlint --edit" not in metadata
