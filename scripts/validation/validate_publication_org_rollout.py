#!/usr/bin/env python3
"""Validate publication-organization rollout reports."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = pathlib.Path("spec/publication-org-rollout.schema.json")
REQUIRED_TASKS = {
    "publication_org_branch_protection",
    "publication_org_secret_rollout",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"Publication-org rollout report not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def validate_report(path: pathlib.Path, require_ready: bool) -> None:
    schema = load_json(SCHEMA_PATH)
    report = cast("dict[str, Any]", load_json(path))
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    validator.validate(report)
    validate_semantics(report, require_ready)


def validate_semantics(report: dict[str, Any], require_ready: bool) -> None:
    tasks = report.get("tasks")
    if not isinstance(tasks, list):
        raise ValidationError("publication-org rollout report requires tasks list")

    seen = {}
    for task in tasks:
        if not isinstance(task, dict):
            continue
        name = task.get("name")
        if not isinstance(name, str):
            continue
        if name in seen:
            raise ValidationError(f"duplicate publication-org task: {name}")
        seen[name] = task

    missing = sorted(REQUIRED_TASKS - set(seen))
    if missing:
        joined = ", ".join(missing)
        raise ValidationError(f"missing publication-org tasks: {joined}")

    all_done = all(seen[name].get("status") == "done" for name in REQUIRED_TASKS)
    missing_details = sorted(
        name
        for name in REQUIRED_TASKS
        if seen[name].get("status") == "done"
        and not (
            isinstance(seen[name].get("detail"), str)
            and cast("str", seen[name].get("detail")).strip()
        )
    )
    blockers = report.get("blockers")
    has_blockers = isinstance(blockers, list) and len(blockers) > 0
    ready = report.get("ready")

    if ready is True and (not all_done or has_blockers):
        raise ValidationError("ready=true requires all tasks done and no blockers")
    if ready is True and missing_details:
        joined = ", ".join(missing_details)
        raise ValidationError(f"ready=true requires done task detail: {joined}")
    if ready is False and all_done and not has_blockers:
        raise ValidationError("ready=false is inconsistent with all tasks done and no blockers")

    if require_ready:
        target = report.get("target_repository")
        if not isinstance(target, dict):
            raise ValidationError("ready publication-org rollout requires target_repository")
        owner = target.get("owner")
        repo = target.get("repo")
        if (
            not isinstance(owner, str)
            or not owner.strip()
            or not isinstance(repo, str)
            or not repo.strip()
        ):
            raise ValidationError("ready publication-org rollout requires target owner and repo")
        if ready is not True:
            raise ValidationError("publication-org rollout is not ready")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Require rollout tasks to be complete with a non-empty target owner/repo",
    )
    parser.add_argument("report", nargs="+", help="Publication-org rollout report JSON path(s)")
    args = parser.parse_args()

    failures = 0
    for raw_path in args.report:
        path = pathlib.Path(raw_path)
        try:
            validate_report(path, args.require_ready)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
