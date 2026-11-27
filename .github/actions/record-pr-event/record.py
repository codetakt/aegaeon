"""Record identity fields from the original GitHub delivery without retaining PR text."""

# ruff: noqa: INP001 -- standalone entry point packaged with the pinned action.
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def main() -> None:
    if os.environ["GITHUB_EVENT_NAME"] != "pull_request":
        message = "Expected a native pull request event"
        raise ValueError(message)
    raw = Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes()
    event = json.loads(raw)
    pr = event["pull_request"]
    base, head = pr["base"], pr["head"]
    repository = os.environ["GITHUB_REPOSITORY"]
    if (
        event["repository"]["full_name"] != repository
        or base["repo"]["full_name"] != repository
        or event["number"] != pr["number"]
    ):
        message = "The pull request identity differs from its workflow"
        raise ValueError(message)
    changes = event.get("changes", {})
    previous_base = None
    if "base" in changes:
        previous_base = changes["base"]["ref"]["from"]
    receipt = {
        "version": 1,
        "repository": repository,
        "number": event["number"],
        "action": event["action"],
        "merged": pr["merged"],
        "change_keys": sorted(changes),
        "sender": event["sender"]["login"],
        "updated_at": pr["updated_at"],
        "head": head["sha"],
        "base": base["ref"],
        "base_sha": base["sha"],
        "previous_base": previous_base,
        "test_sha": os.environ["GITHUB_SHA"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "job": os.environ["GITHUB_JOB"],
        "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
        "event_sha256": hashlib.sha256(raw).hexdigest(),
    }
    with (Path(os.environ["RUNNER_TEMP"]) / "native-pr-event.json").open("x") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
