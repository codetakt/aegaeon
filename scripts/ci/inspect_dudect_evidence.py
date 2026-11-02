"""Inspect external Dudect receipt correspondence without granting CI admission.

The context is an input from a future protected authentication adapter. This
module checks its pinned bytes, but does not authenticate the context itself,
launch measurements, replay raw frames, consume a nonce or issue a check run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, cast

MAX_BYTES = 4 * 1024 * 1024


def require(condition: object, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"non-integer JSON number: {value}")


def decode(data: bytes) -> dict[str, Any]:
    require(len(data) <= MAX_BYTES, "receipt exceeds size bound")
    result = json.loads(
        data,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
        parse_float=reject_constant,
    )
    require(isinstance(result, dict), "JSON object required")
    return cast("dict[str, Any]", result)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_value(value: object) -> None:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid digest")


def integer(value: object) -> None:
    require(type(value) is int and value >= 0, "nonnegative integer required")


def indexed(rows: object, key: str) -> dict[str, dict[str, Any]]:
    require(isinstance(rows, list) and rows, "nonempty inventory required")
    result = {}
    for row in cast("list[Any]", rows):
        require(isinstance(row, dict), "inventory row must be an object")
        name = row.get(key)
        require(isinstance(name, str) and name and name not in result, "duplicate or missing ID")
        result[name] = row
    return result


def check_request(request: dict[str, Any], context: dict[str, Any], now: int) -> None:
    require(request["schema"] == "external-dudect-request/1", "unknown request schema")
    require(request["request_id"] == context["request_id"], "request identity mismatch")
    require(request["subject"] == context["subject"], "revision/artifact/contract subject mismatch")
    subject = request["subject"]
    require(subject["profile"] == "pr", "only the ordinary PR profile is supported")
    for name in (
        "source_tree_sha256",
        "artifact_manifest_sha256",
        "analysis_sha256",
        "environment_sha256",
        "contract_sha256",
    ):
        hash_value(subject[name])
    require(subject["event"] in ("pull_request", "merge_group", "release"), "unknown event")
    require(
        isinstance(subject["repository"], str)
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", subject["repository"]),
        "invalid repository",
    )
    require(
        isinstance(subject["target_revision"], str)
        and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", subject["target_revision"]),
        "invalid target revision",
    )
    for name in ("issued_at", "acquisition_deadline", "recovery_deadline", "expires_at"):
        integer(request[name])
    integer(now)
    require(
        request["issued_at"]
        < request["acquisition_deadline"]
        < request["recovery_deadline"]
        <= request["expires_at"],
        "invalid deadline order",
    )
    require(request["issued_at"] <= now < request["expires_at"], "request expired or future")
    require(context["request_state"] == "open", "request is not open")
    for name in ("request_id", "producer_id", "verifier_id"):
        require(isinstance(context[name], str) and bool(context[name]), "missing identity")


def check_inventory(request: dict[str, Any], context: dict[str, Any]) -> None:
    inventory = indexed(request["inventory"], "id")
    roles = context["case_roles"]
    require(isinstance(roles, dict) and len(roles) == 21, "full 21-case role policy required")
    rounds = context["rounds"]
    require(isinstance(rounds, list) and rounds, "round inventory required")
    for value in rounds:
        integer(value)
    require(len(set(rounds)) == len(rounds), "duplicate round")
    expected = {
        (case, compiler, turn) for case in roles for compiler in ("gcc", "clang") for turn in rounds
    }
    observed = set()
    for row in inventory.values():
        coordinate = row["case_id"], row["compiler"], row["round"]
        integer(row["round"])
        require(
            coordinate in expected and coordinate not in observed, "case/compiler/round mismatch"
        )
        require(row["role"] == roles[row["case_id"]], "case role mismatch")
        hash_value(row["elf_sha256"])
        observed.add(coordinate)
    require(observed == expected, "incomplete case/compiler/round inventory")


def check_producer(
    producer: dict[str, Any], request: dict[str, Any], context: dict[str, Any]
) -> None:
    require(producer["schema"] == "external-dudect-result/1", "unknown producer schema")
    check_inventory(producer, context)
    require(producer["producer_id"] == context["producer_id"], "producer mismatch")
    require(producer["request_sha256"] == context["request_sha256"], "producer request mismatch")
    require(producer["subject"] == request["subject"], "producer subject mismatch")
    require(producer["inventory"] == request["inventory"], "producer ordered inventory mismatch")
    require(producer["execution_kind"] == "fresh_ordinary", "import/diagnostic is not a fresh run")
    require(producer["operation"] == "complete", "execution/recovery not complete")
    for key in ("started_at", "completed_at", "recovered_at"):
        integer(producer[key])
    require(
        request["issued_at"]
        <= producer["started_at"]
        <= producer["completed_at"]
        <= request["acquisition_deadline"],
        "measurement outside acquisition deadline",
    )
    require(
        producer["completed_at"] <= producer["recovered_at"] <= request["recovery_deadline"],
        "recovery outside deadline",
    )
    for key in ("recovery_manifest_sha256", "lifecycle_receipt_sha256"):
        hash_value(producer[key])


def check_replay(
    replay: dict[str, Any], producer: dict[str, Any], context: dict[str, Any], now: int
) -> None:
    require(replay["schema"] == "external-dudect-replay/1", "unknown replay schema")
    require(
        replay["verifier_id"] == context["verifier_id"] != producer["producer_id"],
        "separate verifier identity required",
    )
    require(
        replay["verifier_runtime_sha256"] == context["verifier_runtime_sha256"],
        "verifier runtime mismatch",
    )
    hash_value(replay["verifier_runtime_sha256"])
    require(
        replay["request_sha256"] == context["request_sha256"]
        and replay["producer_sha256"] == context["producer_sha256"],
        "replay binding mismatch",
    )
    require(
        replay["recovery_manifest_sha256"] == producer["recovery_manifest_sha256"],
        "replay recovery mismatch",
    )
    integer(replay["replayed_at"])
    require(producer["recovered_at"] <= replay["replayed_at"] <= now, "invalid replay time")
    expected = indexed(producer["inventory"], "id")
    observations = indexed(producer["observations"], "id")
    results = indexed(replay["results"], "id")
    require(expected.keys() == observations.keys() == results.keys(), "missing or extra result")
    for name, row in results.items():
        check_result(row, observations[name], expected[name])


def check_result(
    row: dict[str, Any], observation: dict[str, Any], expected: dict[str, Any]
) -> None:
    require(row["role"] == expected["role"], "replay role mismatch")
    for key in ("raw_manifest_sha256", "original_decisions_sha256", "effective_decisions_sha256"):
        hash_value(observation[key])
        require(row[key] == observation[key], f"replay {key} mismatch")
    for key in ("collection", "prefix_verification", "numeric_validity", "original_retention"):
        require(row[key] == "complete", f"replay {key} not complete")
    require(row["qualification"] == "observation_contract_satisfied", "required case role not met")
    require(type(row["looks"]) is int and row["looks"] == 8, "incomplete PR look schedule")
    hash_value(row["audit_sha256"])


def inspect(context: dict[str, Any], blobs: dict[str, bytes], now: int) -> dict[str, Any]:
    require(context["schema"] == "external-dudect-inspection-context/1", "unknown context schema")
    parsed = {}
    for key in ("request", "producer", "replay"):
        hash_value(context[key + "_sha256"])
        require(digest(blobs[key]) == context[key + "_sha256"], f"{key} bytes not bound to context")
        parsed[key] = decode(blobs[key])
    check_request(parsed["request"], context, now)
    check_inventory(parsed["request"], context)
    check_producer(parsed["producer"], parsed["request"], context)
    check_replay(parsed["replay"], parsed["producer"], context, now)
    return {
        "status": "correspondence_checked",
        "request_id": context["request_id"],
        "cases": len(parsed["request"]["inventory"]),
        "ci_admission": False,
        "authentication_performed": False,
        "raw_replay_performed": False,
        "request_consumed": False,
    }


def read_bounded(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular receipt file required")
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "receipt exceeds size bound")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("context", "request", "producer", "replay"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument(
        "--now", required=True, type=int, help="Inspection time as UTC epoch seconds"
    )
    args = parser.parse_args()
    try:
        result = inspect(
            decode(read_bounded(args.context)),
            {key: read_bounded(getattr(args, key)) for key in ("request", "producer", "replay")},
            args.now,
        )
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print(json.dumps({"status": "rejected", "reason": str(error), "ci_admission": False}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
