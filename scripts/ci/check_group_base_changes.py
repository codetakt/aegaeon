"""Validate PR base transitions for the members of a native merge group."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from check_merge_readiness import Reader, candidate, check_candidate_runs
from check_pr_titles import group_members
from check_preview_ci import REPOSITORY
from pr_run_event import BASE_HISTORY, check_return, classify_workflows


def group_returns(reader: Reader, group: dict[str, Any], head: str) -> dict[int, Any]:
    members = group_members(REPOSITORY, group, head)
    results = {}
    for number, source in members:
        pr = candidate(reader, number, source)
        history = reader.timeline(BASE_HISTORY, number)
        if history["pageInfo"]["hasPreviousPage"]:
            raise ValueError("Cannot establish complete PR base history")
        if any(row["__typename"] == "BaseRefChangedEvent" for row in history["nodes"]):
            runs = reader.pages(f"actions/runs?head_sha={source}", "workflow_runs")
            checks = reader.pages(f"commits/{source}/check-runs?filter=all", "check_runs")
            retained, _ = classify_workflows(reader, runs, checks, pr)
            check_candidate_runs(retained, pr)
            results[number] = check_return(reader, retained, pr)
            if results[number] is None:
                raise ValueError("Queue member lost its base-change history")
        else:
            results[number] = None
        if reader.timeline(BASE_HISTORY, number) != history:
            raise ValueError("Queue member changed base or reopened during validation")
    if group_members(REPOSITORY, group, head) != members:
        raise ValueError("Merge group changed during base-transition validation")
    return results


def main() -> None:
    if (
        os.environ["GITHUB_EVENT_NAME"] != "merge_group"
        or os.environ["GITHUB_REPOSITORY"] != REPOSITORY
    ):
        raise ValueError("Expected the protected repository's merge group")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    if event["action"] != "checks_requested":
        raise ValueError("Expected a merge group requesting checks")
    result = group_returns(
        Reader({"observations": []}), event["merge_group"], os.environ["GITHUB_SHA"]
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
