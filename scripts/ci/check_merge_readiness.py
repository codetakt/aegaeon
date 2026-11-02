"""Read-only normal-merge admission: exact candidate checks and current main health."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from check_preview_ci import REPOSITORY, WORKFLOWS, latest_attempt, latest_run, require_success

MAIN_WORKFLOWS = (*WORKFLOWS, "verify-fstar-ci.yml")
MAX_PAGES = 10
DEADLINE_SECONDS = 120
SHA = re.compile(r"[0-9a-f]{40}")


class Reader:
    """Finite authenticated reads; retain responses, including partial failed admission."""

    def __init__(self, record: dict[str, Any]) -> None:
        self.record = record
        self.deadline = time.monotonic() + DEADLINE_SECONDS

    def get(self, endpoint: str) -> Any:  # noqa: ANN401 - API shapes checked by consumers
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("GitHub observation deadline exceeded")
        result = subprocess.run(
            ["gh", "api", f"repos/{REPOSITORY}/{endpoint}"],
            capture_output=True,
            text=True,
            check=True,
            timeout=min(30, remaining),
        )
        value = json.loads(result.stdout)
        self.record["observations"].append({"endpoint": endpoint, "response": value})
        return value

    def pages(self, endpoint: str, key: str | None) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        separator = "&" if "?" in endpoint else "?"
        for page in range(1, MAX_PAGES + 1):
            value = self.get(f"{endpoint}{separator}per_page=100&page={page}")
            batch = value[key] if key else value
            if not isinstance(batch, list):
                raise TypeError("Malformed paginated GitHub response")
            rows.extend(batch)
            if len(batch) < 100:
                if key and len(rows) != value["total_count"]:
                    raise ValueError("Incomplete or changing GitHub inventory")
                if len({row["id"] for row in rows}) != len(rows):
                    raise ValueError("Duplicate GitHub rows; completeness not established")
                return rows
        raise ValueError("GitHub page budget exceeded; completeness not established")


def require_sha(value: str) -> None:
    if SHA.fullmatch(value) is None:
        raise ValueError("Expected a full lowercase commit SHA")


def main_revision(reader: Reader) -> str:
    ref = reader.get("git/ref/heads/main")
    if ref["ref"] != "refs/heads/main" or ref["object"]["type"] != "commit":
        raise ValueError("Unexpected main reference")
    revision: str = ref["object"]["sha"]
    require_sha(revision)
    return revision


def candidate(reader: Reader, number: int, head: str) -> dict[str, Any]:
    pr: dict[str, Any] = reader.get(f"pulls/{number}")
    identity = (pr["number"], pr["state"], pr["draft"], pr["merged"], pr["head"]["sha"])
    if identity != (number, "open", False, False, head):
        raise ValueError("Candidate is closed, draft, merged or has changed head")
    if pr["base"]["ref"] != "main" or pr["base"]["repo"]["full_name"] != REPOSITORY:
        raise ValueError("Candidate does not target the protected repository main")
    return pr


def newest(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    selected: dict[Any, dict[str, Any]] = {}
    for row in rows:
        identity = row[key]
        if key == "name":
            identity = (row["app"]["id"], identity)
        if identity not in selected or row["id"] > selected[identity]["id"]:
            selected[identity] = row
    return sorted(selected.values(), key=lambda row: row["id"])


def check_candidate_checks(rows: list[dict[str, Any]], head: str) -> list[dict[str, Any]]:
    if any(row["head_sha"] != head for row in rows):
        raise ValueError("Check run belongs to a different source")
    selected = newest(rows, "name")
    required = [
        row for row in selected if (row["app"]["id"], row["name"]) == (15368, "Required checks")
    ]
    if len(required) != 1:
        raise ValueError("Required checks from GitHub Actions is missing")
    if (required[0]["status"], required[0]["conclusion"]) != ("completed", "success"):
        raise ValueError(f"Required checks is not successful: {required[0]['details_url']}")
    for row in selected:
        if row["status"] != "completed" or row["conclusion"] not in {
            "success",
            "skipped",
            "neutral",
        }:
            raise ValueError(f"Candidate check is not clear: {row['details_url']}")
    return selected


def check_statuses(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = newest(rows, "context")
    for row in selected:
        if row["state"] != "success":
            raise ValueError(f"Candidate commit status is not clear: {row['context']}")
    return selected


def workflow_attempts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        latest_attempt([row for row in rows if (row["event"], row["path"]) == key])
        for key in sorted({(row["event"], row["path"]) for row in rows})
    ]


def check_main_runs(rows: list[dict[str, Any]], revision: str) -> list[dict[str, Any]]:
    push = [row for row in rows if row["event"] == "push"]
    paths = {f".github/workflows/{name}" for name in MAIN_WORKFLOWS}
    paths.update(row["path"] for row in push)
    selected = []
    for path in sorted(paths):
        if not path.startswith(".github/workflows/"):
            raise ValueError("Unexpected main workflow path")
        run = latest_run(
            [row for row in push if row["path"] == path], path.rsplit("/", 1)[1], revision
        )
        require_success(run)
        selected.append(run)
    return selected + check_other_main_runs(rows, revision)


def check_other_main_runs(rows: list[dict[str, Any]], revision: str) -> list[dict[str, Any]]:
    other = [row for row in rows if row["event"] != "push"]
    for row in other:
        identity = (row["repository"]["full_name"], row["head_branch"], row["head_sha"])
        if identity != (REPOSITORY, "main", revision):
            raise ValueError("Unexpected additional main run identity")
        if row["head_repository"]["full_name"] != REPOSITORY:
            raise ValueError("Unexpected additional main head repository")
        if row["event"] not in {"schedule", "workflow_dispatch", "dynamic"}:
            raise ValueError("Unexpected additional main event")
    selected = workflow_attempts(other)
    for row in selected:
        require_success(row)
    return selected


def candidate_run_identity(row: dict[str, Any], pr: dict[str, Any]) -> None:
    identity = (row["repository"]["full_name"], row["head_sha"])
    if identity != (REPOSITORY, pr["head"]["sha"]):
        raise ValueError("Unexpected candidate workflow identity")
    if row["head_repository"]["full_name"] != pr["head"]["repo"]["full_name"]:
        raise ValueError("Candidate workflow belongs to another head repository")


def check_candidate_runs(rows: list[dict[str, Any]], pr: dict[str, Any]) -> list[dict[str, Any]]:
    associated = []
    additional = []
    for row in rows:
        if row["event"] == "pull_request" and pr["number"] not in {
            item["number"] for item in row["pull_requests"]
        }:
            continue
        candidate_run_identity(row, pr)
        if row["event"] == "pull_request":
            associated.append(row)
        elif row["event"] in {"push", "workflow_dispatch", "schedule", "dynamic"}:
            additional.append(row)
        else:
            raise ValueError("Unexpected candidate workflow event")
    selected = workflow_attempts(associated)
    expected = {".github/workflows/pr.yml", ".github/workflows/infrastructure-validation.yml"}
    if not expected <= {row["path"] for row in selected}:
        raise ValueError("Candidate workflow inventory is incomplete")
    selected += workflow_attempts(additional)
    for row in selected:
        require_success(row)
    return selected


def inspect(reader: Reader, number: int, head: str, revision: str) -> dict[str, Any]:
    pr = candidate(reader, number, head)
    rows = reader.pages(f"actions/runs?branch=main&head_sha={revision}", "workflow_runs")
    checks = reader.pages(f"commits/{head}/check-runs?filter=all", "check_runs")
    statuses = reader.pages(f"commits/{head}/statuses", None)
    workflows = reader.pages(f"actions/runs?head_sha={head}", "workflow_runs")
    return {
        "pr": pr["number"],
        "head": head,
        "base": revision,
        "main_runs": check_main_runs(rows, revision),
        "main_inventory": rows,
        "candidate_inventory": workflows,
        "candidate_checks": check_candidate_checks(checks, head),
        "candidate_statuses": check_statuses(statuses),
        "candidate_runs": check_candidate_runs(workflows, pr),
    }


def fingerprint(observation: dict[str, Any]) -> dict[str, Any]:
    """Bind decisions to run/attempt and check IDs; ignore unrelated API decoration."""
    result = {key: observation[key] for key in ("pr", "head", "base")}
    fields = {
        "main_runs": ("id", "run_attempt", "status", "conclusion"),
        "candidate_runs": ("id", "run_attempt", "status", "conclusion"),
        "candidate_checks": ("id", "status", "conclusion"),
        "candidate_statuses": ("id", "state"),
    }
    for key, names in fields.items():
        result[key] = [{name: row[name] for name in names} for row in observation[key]]
    for key in ("main_inventory", "candidate_inventory"):
        names = (
            "id",
            "run_attempt",
            "status",
            "conclusion",
            "event",
            "path",
            "head_sha",
            "run_started_at",
            "updated_at",
        )
        result[key] = [
            {
                **{name: row[name] for name in names},
                "pull_requests": sorted(item["number"] for item in row["pull_requests"]),
            }
            for row in sorted(observation[key], key=lambda row: int(row["id"]))
        ]
    return result


def check(reader: Reader, number: int, head: str, record: dict[str, Any]) -> None:
    require_sha(head)
    revision = main_revision(reader)
    record["main"] = revision
    first = inspect(reader, number, head, revision)
    second = inspect(reader, number, head, revision)
    if fingerprint(first) != fingerprint(second):
        raise ValueError("Check inventory changed during admission; collect fresh evidence")
    if main_revision(reader) != revision:
        raise ValueError("Main advanced during admission; collect fresh evidence")
    candidate(reader, number, head)
    record["selected"] = second
    record["status"] = "normal-ci-clear"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record: dict[str, Any] = {
        "schema": 1,
        "observed_at": datetime.now(UTC).isoformat(),
        "repository": REPOSITORY,
        "pr": args.pr,
        "head": args.head,
        "status": "rejected",
        "observations": [],
        "limits": "Read-only observation, not merge authorization or an atomic GitHub lock. "
        "Signatures, exact-head review, dependency and queue gates remain required. "
        "No repair or incident exception is admitted by this command.",
    }
    try:
        check(Reader(record), args.pr, args.head, record)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        record["reason"] = str(error)
        print(f"Normal merge admission rejected: {error}", file=sys.stderr)
    # Never replace a retained observation or consume an old pass as fresh admission.
    with args.output.open("x") as stream:
        stream.write(json.dumps(record, indent=2) + "\n")
    return 0 if record["status"] == "normal-ci-clear" else 1


if __name__ == "__main__":
    raise SystemExit(main())
