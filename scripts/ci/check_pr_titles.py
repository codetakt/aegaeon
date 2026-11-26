"""Evaluate current PR titles using the checked-out protected base's commitlint policy."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

QUEUE = """
query($owner:String!, $name:String!, $endCursor:String) {
  repository(owner:$owner, name:$name) {
    mergeQueue(branch:"main") {
      entries(first:100, after:$endCursor) {
        nodes { pullRequest { number headRefOid } }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""


def api(*args: str) -> Any:  # noqa: ANN401 - REST objects and paginated GraphQL arrays
    return json.loads(subprocess.check_output(["gh", "api", *args], timeout=60))


def sha(value: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{40}", value):
        raise ValueError("Invalid commit identity")
    return value


def group_members(repository: str, group: dict[str, Any], head: str) -> list[tuple[int, str]]:
    if group["base_ref"] != "refs/heads/main" or group["head_sha"] != head:
        raise ValueError("Merge group does not match this workflow")
    base = sha(group["base_sha"])
    main = sha(api(f"repos/{repository}/git/ref/heads/main")["object"]["sha"])
    owner, name = repository.split("/")
    pages = api(
        "graphql",
        "--paginate",
        "--slurp",
        "-f",
        "query=" + QUEUE,
        "-f",
        "owner=" + owner,
        "-f",
        "name=" + name,
    )
    heads: dict[str, list[int]] = {}
    for page in pages:
        for entry in page["data"]["repository"]["mergeQueue"]["entries"]["nodes"]:
            pr = entry["pullRequest"]
            heads.setdefault(pr["headRefOid"], []).append(pr["number"])

    # A speculative base can itself contain queued PRs. Follow the first-parent
    # chain to protected main and bind every second parent to a single live PR.
    current = sha(head)
    visited = {current}
    members = []
    while current != main:
        parents = api(f"repos/{repository}/git/commits/{current}")["parents"]
        if len(parents) != 2:
            raise ValueError("Expected a queue merge on the first-parent chain")
        parent, source = (sha(item["sha"]) for item in parents)
        candidates = heads.pop(source, [])
        if len(candidates) != 1 or parent in visited:
            raise ValueError("Cannot identify a unique queued PR for a merge parent")
        members.append((candidates[0], source))
        visited.add(parent)
        current = parent
    if not members or base not in visited - {head}:
        raise ValueError("Merge group base or member inventory changed")
    return members


def check_title(repository: str, number: int, head: str, *, queued: bool) -> None:
    pr = api(f"repos/{repository}/pulls/{number}")
    if (
        pr["number"] != number
        or pr["head"]["sha"] != head
        or pr["base"]["ref"] != "main"
        or pr["base"]["repo"]["full_name"] != repository
        or (queued and pr["state"] != "open")
    ):
        raise ValueError(f"PR #{number} changed while evaluating its title")
    title = pr["title"]
    # Keep contributor-controlled text out of the shell program and workflow log.
    result = subprocess.run(
        ["bash", "scripts/ci/lint_pr_title.sh"],
        env={**os.environ, "PR_TITLE": title, "PR_AUTHOR_LOGIN": pr["user"]["login"]},
        capture_output=True,
        check=False,
        timeout=30,
    )
    digest = hashlib.sha256(title.encode()).hexdigest()
    print(f"PR #{number} head={head} title_sha256={digest} lint_exit={result.returncode}")
    if result.returncode:
        raise ValueError(f"PR #{number} did not pass the protected title policy")


def main() -> None:
    repository = os.environ["GITHUB_REPOSITORY"]
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    if event["repository"]["full_name"] != repository:
        raise ValueError("Event belongs to a different repository")
    kind = os.environ["GITHUB_EVENT_NAME"]
    if kind == "pull_request":
        number = event["number"]
        members = [(number, sha(event["pull_request"]["head"]["sha"]))]
    elif kind == "merge_group" and event["action"] == "checks_requested":
        members = group_members(repository, event["merge_group"], os.environ["GITHUB_SHA"])
    else:
        raise ValueError("Unexpected title policy event")
    for number, head in members:
        check_title(repository, number, head, queued=kind == "merge_group")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f"Title policy failed: {error}")
