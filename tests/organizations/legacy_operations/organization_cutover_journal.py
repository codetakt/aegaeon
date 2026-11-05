"""Independent bounded cutover journal; no serving or activation capability.

The root coordinator retains its complete secret plan before registration. Only
its digest is stored here. A journal receipt never substitutes for re-observing
the affected SQL/Redis store after an uncertain cross-store operation.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import TYPE_CHECKING
from uuid import UUID

import organization_recovery as recovery
import organization_recovery_runtime as runtime
from organization_recovery_store import fence, require
from organization_restore_inspect import drained
from psycopg.types.json import Jsonb

if TYPE_CHECKING:
    from organization_recovery_store import Store

MAX_OPERATIONS = 4096
# Later activation requires different live-fence observations. This module only
# implements the offline preparation prefix and cannot mark a cutover complete.
PREPARATION = (
    "registered",
    "content-checked",
    "sql-intent",
    "sql-prepared",
    "token-intent",
    "token-prepared",
    "native-intent",
    "native-validated",
)


def digest(value: str) -> None:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid cutover digest")


def identity(expected: dict, operation: str, plan_sha256: str) -> dict:
    require(
        set(expected) == {"deployment_id", "operation_id", "revision", "state_sha256"},
        "exact cutover fence required",
    )
    for value in [operation, expected["deployment_id"], expected["operation_id"]]:
        require(str(UUID(value)) == value and UUID(value).int != 0, "canonical cutover ID required")
    require(
        type(expected["revision"]) is int and 0 < expected["revision"] < 2**63, "invalid revision"
    )
    digest(plan_sha256)
    digest(expected["state_sha256"])
    return {
        "deployment_id": expected["deployment_id"],
        "operation_id": operation,
        "fence_operation_id": expected["operation_id"],
        "fence_revision": expected["revision"],
        "fence_sha256": expected["state_sha256"],
        "plan_sha256": plan_sha256,
    }


@contextmanager
def locked(control: Store, expected: dict):
    drained(control)
    recovery.checked_catalog(control)
    with control.connection.transaction():
        fence(control, expected["deployment_id"])
        current = runtime.state(control, expected["deployment_id"])
        require(
            current["parent"]["operation_id"] == expected["operation_id"]
            and current["parent"]["revision"] == expected["revision"]
            and runtime.digest(current) == expected["state_sha256"],
            "cutover fence changed",
        )
        yield


def selected(control: Store, key: dict) -> dict | None:
    rows = control.rows(
        "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c "
        "WHERE deployment_id=%s AND operation_id=%s FOR UPDATE",
        (key["deployment_id"], key["operation_id"]),
    )
    if not rows:
        return None
    row = rows[0][0]
    require(
        all(row[name] == value for name, value in key.items())
        and row["principal"] == control.one("SELECT session_user::text"),
        "cutover plan or administrator conflicts",
    )
    require(
        not row["completed"] and not row["aborted"] and row["step"] < len(PREPARATION),
        "cutover is outside the preparation prefix",
    )
    require(
        len(row["receipts"]) == row["step"]
        and all(
            type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in row["receipts"]
        ),
        "cutover receipt history differs",
    )
    return row


def pending_or_registered(control: Store, deployment: str, operation: str) -> bool:
    return control.one(
        "SELECT EXISTS(SELECT FROM organization_witness.cutover_operations "
        "WHERE deployment_id=%s AND (operation_id=%s OR (NOT completed AND NOT aborted)))",
        (deployment, operation),
    )


def register(control: Store, expected: dict, operation: str, plan_sha256: str) -> dict:
    key = identity(expected, operation, plan_sha256)
    with locked(control, expected):
        previous = selected(control, key)
        if previous is not None:
            return previous
        require(
            not pending_or_registered(control, key["deployment_id"], operation),
            "another cutover is pending",
        )
        require(
            control.one(
                "SELECT count(*) FROM organization_witness.cutover_operations "
                "WHERE deployment_id=%s",
                (key["deployment_id"],),
            )
            < MAX_OPERATIONS,
            "cutover history capacity exhausted",
        )
        control.connection.execute(
            "INSERT INTO organization_witness.cutover_operations "
            "(deployment_id,operation_id,fence_operation_id,fence_revision,"
            "fence_sha256,plan_sha256) "
            "VALUES(%s,%s,%s,%s,%s,%s)",
            tuple(key.values()),
        )
        return selected(control, key)


def inspect(control: Store, expected: dict, operation: str, plan_sha256: str) -> dict:
    key = identity(expected, operation, plan_sha256)
    with locked(control, expected):
        row = selected(control, key)
        require(row is not None, "cutover was not registered")
        return row


def advance(  # noqa: PLR0913,PLR0917 — exact operation plus expected predecessor
    control: Store, expected: dict, operation: str, plan_sha256: str, predecessor: str, receipt: str
) -> dict:
    key = identity(expected, operation, plan_sha256)
    digest(receipt)
    require(predecessor in PREPARATION[:-1], "unsupported cutover transition")
    before = PREPARATION.index(predecessor)
    with locked(control, expected):
        row = selected(control, key)
        require(row is not None, "cutover was not registered")
        if row["step"] == before + 1:
            require(row["receipts"][-1] == receipt, "cutover receipt conflicts")
            return row
        require(row["step"] == before, "cutover predecessor differs")
        return control.one(
            "UPDATE organization_witness.cutover_operations SET step=step+1,receipts=%s "
            "WHERE deployment_id=%s AND operation_id=%s AND step=%s "
            "RETURNING to_jsonb(cutover_operations)",
            (Jsonb([*row["receipts"], receipt]), key["deployment_id"], operation, before),
        )
