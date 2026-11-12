"""Require complete, same-event Core partitions and preserve separate invocations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from run_core_pr_checks import (
    DERIVATION,
    SHARDS,
    SYSTEM,
    build_command,
    event_context,
    partition,
    split_core_checks,
)

FILES = (
    "ci-check-ownership.json",
    "core-build-observations.jsonl",
    "organization-userns-core.json",
)
JSON_LIMIT = 4 * 1024 * 1024
TRACE_LIMIT = 65 * 1024 * 1024


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - assertion, not a mode.
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def object_json(data: bytes) -> dict[str, Any]:
    value = json.loads(data, object_pairs_hook=unique_object)
    require(isinstance(value, dict), "expected a JSON object")
    return dict(value)


def read_object(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        data = source.read(JSON_LIMIT + 1)
    require(len(data) <= JSON_LIMIT, "JSON evidence exceeds bound")
    return object_json(data)


def derivations(value: Any) -> dict[str, str]:  # noqa: ANN401 - untrusted JSON boundary.
    require(isinstance(value, dict) and bool(value), "missing derivation inventory")
    require(
        all(
            isinstance(k, str) and isinstance(v, str) and DERIVATION.fullmatch(v)
            for k, v in value.items()
        ),
        "invalid derivation inventory",
    )
    return dict(value)


def validate_plan(
    record: dict[str, Any], shard: str, context: dict[str, str], *, all_checks: bool
) -> dict[str, dict[str, str]]:
    require(record["schema"] == "core-check-shard/1", "unknown shard schema")
    require(record["system"] == SYSTEM and record["shard"] == shard, "wrong system or shard")
    require(record["context"] == context, "wrong source, run, attempt or event")
    require(record["all_checks"] is all_checks, "delegation mode mismatch")
    require(
        all_checks or context["GITHUB_EVENT_NAME"] in {"pull_request", "merge_group"},
        "delegation is only supported by full PR/group validation",
    )
    checks = derivations(record["checks"])
    packages = derivations(record["formal_packages"])
    owners = partition(checks, packages)
    if all_checks:
        owners = {"core": checks, "verification": {}}
    shards = split_core_checks(owners["core"])
    require(record["owners"] == owners and record["shards"] == shards, "incomplete ownership")
    return shards


def validate_trace(path: Path, command: list[str], context: dict[str, str]) -> str:
    digest = hashlib.sha256()
    size = 0
    start: dict[str, Any] | None = None
    finished = False
    with path.open("rb") as source:
        while line := source.readline(TRACE_LIMIT - size + 1):
            size += len(line)
            require(size <= TRACE_LIMIT, "trace exceeds bound")
            digest.update(line)
            row = object_json(line)
            require(not finished, "extra invocation or output after finish")
            if start is None:
                require(row["event"] == "start" and bool(row["invocation"]), "missing build start")
                require(row["command"] == command, "build targets or capacity differ")
                require(
                    {key: row["context"][key] for key in context} == context,
                    "build context differs",
                )
                start = row
                continue
            require(row["invocation"] == start["invocation"], "mixed build invocations")
            if row["event"] == "finish":
                require(
                    type(row["returncode"]) is int and row["returncode"] == 0,
                    "failed or incomplete build",
                )
                require(row["truncated"] is False, "truncated build trace")
                finished = True
            else:
                require(row["event"] == "output" and isinstance(row["text"], str), "invalid event")
    require(finished, "missing build finish")
    return digest.hexdigest()


def validate_namespace(record: dict[str, Any], command: list[str]) -> None:
    require(record["command"] == command, "namespace command differs")
    require(
        type(record["command_returncode"]) is int and record["command_returncode"] == 0,
        "namespace command failed",
    )
    failures = {
        "error",
        "cancellation",
        "recovery",
        "nested_cleanup_unconfirmed",
        "policy_removal_deferred",
        "policy_recovery_error",
    }
    require(not failures.intersection(record), "namespace cancellation or cleanup failure")
    require(record["unconfirmed_groups"] == [], "unconfirmed namespace process groups")
    require(
        record["restriction_after"] == record["restriction_before"],
        "namespace restriction changed",
    )
    receipts = record["nested_cleanup_receipts"]
    require(
        isinstance(receipts, list)
        and bool(receipts)
        and all(isinstance(row, dict) and row.get("confirmed") is True for row in receipts),
        "missing or unconfirmed nested cleanup",
    )
    if record.get("install_attempted"):
        require(
            record["profile_absent"] is True and record["after"]["passed"] is True,
            "namespace profile cleanup or probe failed",
        )
    else:
        require(record["before"]["passed"] is True, "namespace probe failed")


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def aggregate(
    directory: Path, context: dict[str, str], results: dict[str, Any], *, all_checks: bool
) -> dict[str, Any]:
    require(
        results == {"ci": "success", "check-shards": "success"},
        "every producer job must succeed",
    )
    require(
        {p.name for p in directory.iterdir()} == {f"core-check-shard-{s}" for s in SHARDS},
        "missing, duplicate or unknown shard artifact",
    )
    reference: dict[str, Any] | None = None
    evidence: dict[str, Any] = {}
    for shard in SHARDS:
        root = directory / f"core-check-shard-{shard}"
        require({p.name for p in root.iterdir()} == set(FILES), "incomplete shard artifact")
        record = read_object(root / FILES[0])
        shards = validate_plan(record, shard, context, all_checks=all_checks)
        common = {k: v for k, v in record.items() if k != "shard"}
        if reference is None:
            reference = common
        require(common == reference, "evaluated inventories differ between runners")
        trace_hash = validate_trace(root / FILES[1], build_command(shards[shard]), context)
        command = ["python3", "scripts/ci/run_core_pr_checks.py"]
        if all_checks:
            command.append("--all-checks")
        command += ["--shard", shard]
        validate_namespace(read_object(root / FILES[2]), command)
        evidence[shard] = {
            "checks": shards[shard],
            "sha256": {
                FILES[0]: sha256(root / FILES[0]),
                FILES[1]: trace_hash,
                FILES[2]: sha256(root / FILES[2]),
            },
        }
    return {
        "schema": "core-check-partitions/1",
        "context": context,
        "all_checks": all_checks,
        "inventory": reference,
        "producer_results": results,
        "shards": evidence,
        "scope": (
            "Functional check accounting; no fresh execution or qualification "
            "inferred from cache reuse."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--all-checks", action="store_true")
    args = parser.parse_args()
    try:
        results = object_json(os.environ["CORE_PRODUCER_RESULTS"].encode())
        result = aggregate(args.directory, event_context(), results, all_checks=args.all_checks)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Core partition validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
