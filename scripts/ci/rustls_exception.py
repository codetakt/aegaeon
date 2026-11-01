"""Admit only PR228's owner-authorized security integration exception."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

BASE = "400420225cbefcf504d68f35d639abff7ef924ba"
PRODUCT = "48b05eb0dbf716d130c69268d1612ada2a825385"
REPOSITORY = "codetakt/aegaeon"
BRANCH = "fix/rustls-security-update"
CI_PATHS = {
    ".github/workflows/pr.yml",
    "scripts/ci/rustls_exception.py",
    "scripts/ci/run_rustls_exception.sh",
    "tests/ci/test_rustls_exception.py",
}
REGULAR_JOBS = {
    "plan",
    "docs",
    "integrity",
    "core",
    "lint",
    "security",
    "verification",
    "compliance",
    "kms",
    "container",
}


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - assertion predicate
    if not condition:
        raise ValueError(message)


def selects_exception(event_name: str, event: dict[str, Any]) -> bool:
    if event_name == "pull_request":
        return bool(event["number"] == 228)
    require(event_name == "merge_group", "unsupported event")
    ref = event["merge_group"]["head_ref"]
    return re.fullmatch(r"refs/heads/gh-readonly-queue/main/pr-228-[0-9a-f]+", ref) is not None


def validate_context(context: dict[str, Any]) -> None:
    require(context["repository"] == REPOSITORY, "wrong repository")
    require(context["actual_base"] == BASE, "main changed: exception needs new review")
    pr = context["pr"]
    require(pr["number"] == 228 and pr["state"] == "open" and not pr["draft"], "wrong PR state")
    require(pr["base"]["ref"] == "main" and pr["base"]["sha"] == BASE, "wrong PR base")
    require(pr["head"]["repo"]["full_name"] == REPOSITORY, "fork exception forbidden")
    require(pr["head"]["ref"] == BRANCH, "wrong source branch")
    require(pr["head"]["sha"] == context["source_head"], "source changed")
    require("[skip ci]" in pr["title"], "merge title must suppress legacy push timing")
    require(context["source_descends_product"], "security revision is not an ancestor")
    require(context["source_parents_linear"], "exception additions must be linear")
    require(set(context["changed_paths"]) == CI_PATHS, "non-CI changes or incomplete exception")
    require(context["regular_file_modes"], "unexpected exception file mode")
    require(context["test_tree"] == context["source_tree"], "test contains other changes")
    signatures = context["signatures"]
    require(bool(signatures) and signatures[0]["sha"] == PRODUCT, "missing security commit")
    require(signatures[-1]["sha"] == context["source_head"], "incomplete signature inventory")
    require(
        all(row["verified"] and row["reason"] == "valid" for row in signatures), "invalid signature"
    )
    validate_event_context(context)


def validate_event_context(context: dict[str, Any]) -> None:
    if context["event_name"] == "pull_request":
        event_pr = context["event"]["pull_request"]
        require(event_pr["head"]["sha"] == context["source_head"], "stale PR event")
        require(event_pr["base"]["sha"] == BASE, "stale PR base")
    else:
        group = context["event"]["merge_group"]
        require(group["base_sha"] == BASE, "multi-entry or changed-base merge group")
        require(group["base_ref"] == "refs/heads/main", "wrong merge-group base ref")
        require(group["head_sha"] == context["test_sha"], "wrong merge-group test revision")
        require("[skip ci]" in context["test_message"], "merge commit would restart timing")


def validate_results(needs: dict[str, Any]) -> None:
    require(set(needs) == REGULAR_JOBS | {"exception", "security_patch"}, "changed job inventory")
    require(needs["exception"]["result"] == "success", "exception admission failed")
    require(needs["exception"]["outputs"].get("admitted") == "true", "exception not admitted")
    require(needs["security_patch"]["result"] == "success", "security checks did not succeed")
    require(all(needs[name]["result"] == "skipped" for name in REGULAR_JOBS), "regular lane ran")


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def git(*args: str) -> str:
    return command("git", "--no-replace-objects", *args)


def api(path: str) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(command("gh", "api", f"repos/{REPOSITORY}/{path}"))
    return result


def collect_context(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    pr = api("pulls/228")
    source = pr["head"]["sha"]
    require(re.fullmatch(r"[0-9a-f]{40}", source) is not None, "invalid source revision")
    test = os.environ["GITHUB_SHA"]
    require(git("rev-parse", "HEAD") == test, "checkout differs from event")
    require(not git("diff", "HEAD", "--"), "tracked files modified before admission")
    command("git", "fetch", "--no-tags", "origin", source)
    commits = git("rev-list", "--reverse", f"{BASE}..{source}").splitlines()
    signatures = []
    for sha in commits:
        verification = api(f"commits/{sha}")["commit"]["verification"]
        signatures.append(
            {"sha": sha, "verified": verification["verified"], "reason": verification["reason"]}
        )
    changes = git("diff", "--name-only", PRODUCT, source).splitlines()
    modes = [git("ls-tree", source, "--", path).split()[0] for path in changes]
    return {
        "repository": os.environ["GITHUB_REPOSITORY"],
        "actual_base": api("git/ref/heads/main")["object"]["sha"],
        "pr": pr,
        "event_name": event_name,
        "event": event,
        "source_head": source,
        "source_descends_product": git("merge-base", PRODUCT, source) == PRODUCT,
        "source_parents_linear": all(
            len(git("show", "-s", "--format=%P", sha).split()) == 1 for sha in commits
        ),
        "changed_paths": changes,
        "regular_file_modes": all(mode == "100644" for mode in modes),
        "test_sha": test,
        "test_tree": git("rev-parse", "HEAD^{tree}"),
        "source_tree": git("rev-parse", f"{source}^{{tree}}"),
        "test_message": git("show", "-s", "--format=%B", test),
        "signatures": signatures,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", action="store_true")
    args = parser.parse_args()
    if args.results:
        validate_results(json.loads(os.environ["PR_NEEDS_JSON"]))
        print("Required checks passed under PR228's documented, scoped CI exception.")
        return
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    name = os.environ["GITHUB_EVENT_NAME"]
    admitted = selects_exception(name, event)
    if admitted:
        context = collect_context(name, event)
        validate_context(context)
        output = Path("artifacts/rustls-ci-exception")
        output.mkdir(parents=True, exist_ok=True)
        (output / "admission.json").write_text(json.dumps(context, indent=2) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(f"admitted={str(admitted).lower()}\n")


if __name__ == "__main__":
    main()
