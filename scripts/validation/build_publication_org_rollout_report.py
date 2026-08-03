#!/usr/bin/env python3
"""Build and validate a publication-organization rollout report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any

from jsonschema import ValidationError

VALIDATION_DIR = pathlib.Path(__file__).resolve().parent
if str(VALIDATION_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATION_DIR))

import validate_publication_org_rollout  # noqa: E402

TASKS = (
    "publication_org_branch_protection",
    "publication_org_secret_rollout",
)


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_task(raw_value: str) -> tuple[str, str, str | None]:
    parts = raw_value.split("=", 2)
    if len(parts) < 2:
        raise argparse.ArgumentTypeError(
            "--task must use name=status or name=status=detail",
        )
    name = parts[0]
    status = parts[1]
    detail = parts[2] if len(parts) == 3 else None
    if name not in TASKS:
        raise argparse.ArgumentTypeError(f"unsupported publication task: {name}")
    if status not in {"pending", "done"}:
        raise argparse.ArgumentTypeError(f"unsupported status for {name}: {status}")
    return name, status, detail


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    task_values: dict[str, tuple[str, str | None]] = dict.fromkeys(
        TASKS,
        ("pending", None),
    )
    for name, status, detail in args.task:
        task_values[name] = (status, detail)

    blockers: list[str] = []
    tasks = []
    for name in TASKS:
        status, detail = task_values[name]
        if status != "done":
            blockers.append(f"publication-org task still pending: {name}")
        if status == "done" and (detail is None or not detail.strip()):
            blockers.append(f"publication-org done task lacks detail: {name}")
        tasks.append(
            {
                "name": name,
                "status": status,
                "detail": detail,
            },
        )

    if args.owner is None or not args.owner.strip():
        blockers.append("target repository owner is required")
    if args.repo is None or not args.repo.strip():
        blockers.append("target repository repo is required")

    ready = not blockers
    return {
        "$schema": "https://aegaeon.dev/spec/publication-org-rollout.schema.json",
        "schema_version": 1,
        "generated_at": args.generated_at,
        "rollout_target": "released-client-claim",
        "target_repository": {
            "owner": args.owner,
            "repo": args.repo,
            "branch": args.branch,
        },
        "tasks": tasks,
        "ready": ready,
        "blockers": blockers,
    }


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True, help="Publication repository owner")
    parser.add_argument("--repo", required=True, help="Publication repository name")
    parser.add_argument("--branch", default="main", help="Publication branch")
    parser.add_argument(
        "--task",
        action="append",
        type=parse_task,
        required=True,
        help="Task status as name=status=detail. Repeat for every required task.",
    )
    parser.add_argument("--generated-at", default=utc_now())
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    report = build_report(args)
    write_json(args.out, report)
    try:
        validate_publication_org_rollout.validate_report(args.out, require_ready=True)
    except (ValidationError, SystemExit) as exc:
        print(f"[invalid] {args.out}: {exc}", file=sys.stderr)
        return 1
    print(f"[ok] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
