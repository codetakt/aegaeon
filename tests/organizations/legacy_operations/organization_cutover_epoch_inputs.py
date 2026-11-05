"""Root-custodied epoch intent derivation from already accepted cutover evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import UUID, uuid4

import organization_cutover_plan as plans
import organization_cutover_validation as validation
import organization_recovery as recovery
import organization_recovery_runtime as runtime
from organization_recovery_store import require

NATIVE = Path("@epochPreparer@")
NATIVE_BINARY = Path("@epochBinary@")
MAX_INTENT = 256 * 1024


def read(directory: Path, name: str, limit: int = plans.MAX_PLAN) -> tuple[dict, str]:
    data = recovery.private_file(directory / name, limit)
    return json.loads(data), hashlib.sha256(data).hexdigest()


def retain(directory: Path, descriptor: int, name: str, value: dict) -> str:
    if (directory / name).exists():
        previous, digest = read(directory, name, runtime.MAX_STATE + 1)
        require(previous == value, "retained epoch inputs differ")
        return digest
    return recovery.retain(descriptor, name, value)


def binding(context: validation.Context, original: dict, native: dict, hashes: dict) -> dict:
    require(
        native["planSha256"] == context.plan.sha256
        and native["binding"] == validation.binding(context.configuration),
        "epoch native validation inputs differ",
    )
    expected = {row["environment_id"] for row in original["children"]}
    namespaces = {row["id"]: row for row in context.configuration["environments"]}
    results = native["results"]
    require(
        expected == set(namespaces)
        and len(results) == len(expected)
        and {row["namespace"]["id"] for row in results} == expected
        and all(row["namespace"] == namespaces[row["namespace"]["id"]] for row in results),
        "epoch complete native namespace inventory differs",
    )
    for path in (NATIVE, NATIVE_BINARY):
        require(path.is_file() and str(path).startswith("/nix/store/"), "fixed epoch tool required")
    return {
        "version": 1,
        "planSha256": context.plan.sha256,
        "files": hashes,
        "validation": native["binding"],
        "nativeExecutable": str(NATIVE),
        "nativeWrapperSha256": hashlib.sha256(NATIVE.read_bytes()).hexdigest(),
        "nativeBinary": str(NATIVE_BINARY),
        "nativeBinarySha256": hashlib.sha256(NATIVE_BINARY.read_bytes()).hexdigest(),
    }


def revision_capacity(original: dict) -> None:
    require(
        all(
            type(row["revision"]) is int and 0 < row["revision"] < 2**63 - 3
            for row in [original["parent"], *original["children"]]
        ),
        "epoch revisions cannot complete both preparation and activation",
    )


def derive(  # noqa: PLR0913,PLR0917 — fixed evidence plus retained identities
    operation: str, original: dict, native: dict, comparison: dict, acceptance: str, ids: dict
) -> dict:
    revision_capacity(original)
    values = [ids["primary"], ids["token"], *ids["epochs"]]
    require(
        len(ids["epochs"]) == len(original["children"]) + 1
        and len(set(values)) == len(values)
        and all(str(UUID(value)) == value and UUID(value).int != 0 for value in values),
        "fresh unique epoch identities required",
    )
    previous = [original["parent"], *original["children"]]
    require(
        not set(values).intersection(
            row[key] for row in previous for key in ("epoch", "primary_id", "token_store_id")
        ),
        "epoch identities reuse original authority",
    )
    results = {row["namespace"]["id"]: row for row in native["results"]}
    histories = [
        results[row["environment_id"]]["native"]["history"]["history"]
        for row in original["children"]
    ]

    def transition(before: dict, index: int, history_digest: str) -> dict:
        return {
            "operation_id": before["operation_id"],
            "revision": before["revision"],
            "selection": {
                "epoch": ids["epochs"][index],
                "primary": ids["primary"],
                "token_store": ids["token"],
                "source_sha256": runtime.digest(comparison["content"]),
                "history_sha256": history_digest,
                "acceptance_sha256": acceptance,
            },
        }

    observed = native["results"][0]["native"]["runtime"]
    return {
        "version": 1,
        "deployment_id": original["parent"]["deployment_id"],
        "cutover_operation_id": operation,
        "parent": transition(original["parent"], 0, runtime.digest(histories)),
        "children": [
            {
                "environment_id": row["environment_id"],
                "issuer": results[row["environment_id"]]["namespace"]["issuer"],
                "transition": transition(row, index + 1, histories[index]["digest"]),
            }
            for index, row in enumerate(original["children"])
        ],
        "stores": {
            "primary": observed["primary"],
            "control": observed["control"],
            "token": observed["tokenStore"],
        },
    }


def intent(  # noqa: PLR0913,PLR0917 — complete retained context
    directory: Path,
    descriptor: int,
    operation: str,
    original: dict,
    native: dict,
    comparison: dict,
    acceptance: str,
    *,
    registered: bool,
) -> tuple[dict, str]:
    path = directory / "epochs.json"
    if path.exists():
        value, digest = read(directory, path.name, MAX_INTENT)
        ids = {
            "primary": value["parent"]["selection"]["primary"],
            "token": value["parent"]["selection"]["token_store"],
            "epochs": [
                value["parent"]["selection"]["epoch"],
                *[row["transition"]["selection"]["epoch"] for row in value["children"]],
            ],
        }
        require(
            value == derive(operation, original, native, comparison, acceptance, ids),
            "epoch intent derivation differs",
        )
        return value, digest
    require(not registered, "registered epoch intent missing; never regenerate")
    ids = {
        "primary": str(uuid4()),
        "token": str(uuid4()),
        "epochs": [str(uuid4()) for _ in range(len(original["children"]) + 1)],
    }
    value = derive(operation, original, native, comparison, acceptance, ids)
    require(len(plans.canonical(value)) <= MAX_INTENT, "epoch intent exceeds native input bound")
    return value, recovery.retain(descriptor, path.name, value)
