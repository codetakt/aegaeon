"""Bind PR/group validation to event commits and the protected base policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

BOOTSTRAP_BASE = "b162b7b8440307ad210ce2c3ef846c0a0cbd8e33"
COMMIT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()


def commit_id(value: object) -> str:
    if not isinstance(value, str) or not COMMIT_ID.fullmatch(value):
        raise ValueError("expected a full commit ID")
    if git("cat-file", "-t", value) != "commit":
        raise ValueError("event revision is not a commit")
    return value


def event_range(
    event: dict[str, Any], event_name: str, test_sha: str, trusted_base: str
) -> tuple[str, str]:
    if event_name == "pull_request":
        change = event["pull_request"]
        if change["base"]["ref"] != "main":
            raise ValueError("PR must target protected main")
        base, head = change["base"]["sha"], change["head"]["sha"]
        if base != trusted_base:
            raise ValueError("PR policy authority differs from event base")
    elif event_name == "merge_group":
        change = event["merge_group"]
        if event["action"] != "checks_requested" or change["base_ref"] != "refs/heads/main":
            raise ValueError("group must request checks for protected main")
        base, head = change["base_sha"], change["head_sha"]
        if head != test_sha:
            raise ValueError("group head differs from GITHUB_SHA")
        if not isinstance(change["head_ref"], str) or not change["head_ref"].startswith(
            "refs/heads/gh-readonly-queue/main/"
        ):
            raise ValueError("group head ref is not a main queue ref")
    else:
        raise ValueError("only PR and merge_group validation is supported")
    return commit_id(base), commit_id(head)


def context(
    event: dict[str, Any], event_name: str, test_sha: str, trusted_base: str
) -> dict[str, str]:
    """PR heads may diverge from base; both must be ancestors of the tested merge."""
    test_sha = commit_id(test_sha)
    trusted_base = commit_id(trusted_base)
    base, head = event_range(event, event_name, test_sha, trusted_base)
    for ancestor in (base, head, trusted_base):
        git("merge-base", "--is-ancestor", ancestor, test_sha)
    if git("rev-parse", "HEAD") != test_sha:
        raise ValueError("checkout does not match the event test commit")
    return {
        "event": event_name,
        "event_base": base,
        "base": trusted_base,
        "source_head": head,
        "test_sha": test_sha,
        "test_tree": git("rev-parse", f"{test_sha}^{{tree}}"),
    }


def bootstrap_allowed(event: dict[str, Any], bound: dict[str, str]) -> bool:
    return (
        bound["event"] == "pull_request"
        and bound["base"] == BOOTSTRAP_BASE
        and event["pull_request"]["head"]["ref"] == "ci/merge-queue-validation"
        and event["pull_request"]["head"]["repo"]["full_name"] == event["repository"]["full_name"]
    )


def verify_signatures(base: str, head: str, repository: str) -> list[dict[str, Any]]:
    """Ask GitHub about every introduced commit, including synthetic group commits."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid GitHub repository")
    commits = git("rev-list", "--reverse", f"{base}..{head}").splitlines()
    if not commits:
        raise ValueError("no introduced commits")
    records = []
    for sha in commits:
        commit_id(sha)
        response = subprocess.check_output(
            ["gh", "api", f"repos/{repository}/commits/{sha}"], text=True, timeout=60
        )
        data = json.loads(response)
        verification = data["commit"]["verification"]
        if (
            data["sha"] != sha
            or verification.get("verified") is not True
            or verification.get("reason") != "valid"
        ):
            raise ValueError(f"commit {sha} lacks valid GitHub signature verification")
        records.append({"sha": sha, "verified": True, "reason": "valid"})
    return records


def classify(bound: dict[str, str], output: Path) -> dict[str, Any]:
    """Only protected-base classifier/policy bytes determine the selected lanes."""
    base, head = bound["base"], bound["source_head"]
    paths = ("scripts/ci/pr_plan.py", "ci/pr-policy.json")
    try:
        sources = [
            subprocess.check_output(["git", "show", f"{base}:{path}"], stderr=subprocess.PIPE)
            for path in paths
        ]
    except subprocess.CalledProcessError:
        return {"scope": "full", "fallback": "base revision has no PR classification policy"}
    with tempfile.TemporaryDirectory() as temporary:
        trusted = Path(temporary)
        script, policy = trusted / "pr_plan.py", trusted / "policy.json"
        script.write_bytes(sources[0])
        policy.write_bytes(sources[1])
        subprocess.run(
            [
                sys.executable,
                str(script),
                "--base",
                base,
                "--head",
                head,
                "--policy",
                str(policy),
                "--output",
                str(output),
            ],
            check=True,
            # Publish scope only after signatures and context have succeeded.
            env={key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"},
        )
        result: dict[str, Any] = json.loads(output.read_text())
        return result


def run(*, bootstrap: bool) -> None:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    bound = context(
        event,
        os.environ["GITHUB_EVENT_NAME"],
        os.environ["GITHUB_SHA"],
        os.environ["TRUSTED_BASE_SHA"],
    )
    if bootstrap and not bootstrap_allowed(event, bound):
        raise ValueError("protected-base verifier missing outside the preparation PR")
    evidence: dict[str, Any] = {
        **bound,
        "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "verifier_authority": "bootstrap candidate: mandatory manual signature gate"
        if bootstrap
        else "protected base",
    }
    output = Path("ci-validation.json")
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    evidence["signatures"] = verify_signatures(
        bound["base"], bound["source_head"], os.environ["GITHUB_REPOSITORY"]
    )
    evidence["signatures_valid"] = True
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    plan = classify(bound, Path("ci-plan.json"))
    plan.update(bound)
    Path("ci-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(f"scope={plan['scope']}\nbase={bound['base']}\n")
        stream.write(f"source_head={bound['source_head']}\ntest_sha={bound['test_sha']}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    try:
        run(bootstrap=args.bootstrap)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Change validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
