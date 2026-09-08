"""Require successful main-push workflows for the exact preview source commit."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY = "codetakt/aegaeon"
WORKFLOWS = (
    "ci.yml",
    "lint.yml",
    "security.yml",
    "verification.yml",
    "compliance.yml",
    "oidc-kms-parity.yml",
    "docker-build.yml",
    "performance.yml",
)


def latest_run(runs: list[dict[str, Any]], workflow: str, revision: str) -> dict[str, Any]:
    if not runs:
        raise ValueError(f"no main-push run for {workflow} at {revision}")
    for run in runs:
        identity = (
            run["repository"]["full_name"],
            run["head_repository"]["full_name"],
            run["event"],
            run["head_branch"],
            run["head_sha"],
            run["path"],
        )
        expected = (
            REPOSITORY,
            REPOSITORY,
            "push",
            "main",
            revision,
            f".github/workflows/{workflow}",
        )
        if identity != expected:
            raise ValueError(f"unexpected workflow run identity for {workflow}")
    # A later failed or pending run must not be rescued by an earlier success.
    return max(runs, key=lambda run: int(run["id"]))


def require_success(run: dict[str, Any]) -> None:
    if (run["status"], run["conclusion"]) != ("completed", "success"):
        raise ValueError(f"preview requires successful CI: {run['html_url']}")


def api(endpoint: str) -> Any:  # noqa: ANN401 - untrusted JSON is checked by the caller
    return json.loads(subprocess.check_output(["gh", "api", endpoint, "--paginate", "--slurp"]))


def source_identity(lock: Path) -> dict[str, Any]:
    data = json.loads(lock.read_text())
    node = data["nodes"][data["root"]]["inputs"]["aegaeon"]
    source: dict[str, Any] = data["nodes"][node]["locked"]
    if (source["type"], source["owner"], source["repo"]) != ("github", "codetakt", "aegaeon"):
        raise ValueError("preview must lock the codetakt/aegaeon source repository")
    if re.fullmatch(r"[0-9a-f]{40}", source["rev"]) is None:
        raise ValueError("preview source must have a full locked commit SHA")
    return source


def check_workflows(revision: str, record: dict[str, Any]) -> None:
    for workflow in WORKFLOWS:
        pages = api(
            f"repos/{REPOSITORY}/actions/workflows/{workflow}/runs"
            f"?event=push&branch=main&head_sha={revision}&per_page=100"
        )
        runs = [run for page in pages for run in page["workflow_runs"]]
        selected = latest_run(runs, workflow, revision)
        record["runs"].append(selected)
        require_success(selected)


def check(revision: str, record: dict[str, Any]) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("revision must be a full Git commit SHA")
    ref = api(f"repos/{REPOSITORY}/git/ref/heads/main")[0]
    record["main_ref"] = ref
    if ref["object"]["type"] != "commit" or ref["object"]["sha"] != revision:
        raise ValueError("preview source must still be the current main commit")
    check_workflows(revision, record)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-lock", type=Path, default=Path(".flakehub/flake.lock"))
    args = parser.parse_args()
    record: dict[str, Any] = {"revision": args.revision, "status": "rejected", "runs": []}
    try:
        check(args.revision, record)
        source = source_identity(args.source_lock)
        record["source"] = {"locked": source, "runs": []}
        check_workflows(source["rev"], record["source"])
        record["status"] = "accepted"
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        record["reason"] = str(error)
        print(f"Preview CI gate rejected: {error}", file=sys.stderr)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    return 0 if record["status"] == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
