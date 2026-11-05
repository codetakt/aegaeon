"""Exact offline epoch states; never weaken the old fenced-state observer."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import organization_cutover_journal as journal
import organization_recovery as recovery
import organization_recovery_runtime as runtime
import organization_restore_inspect as restore
from organization_recovery_store import require
from psycopg.types.json import Jsonb

if TYPE_CHECKING:
    from organization_recovery_store import Store

EPOCH_INTENT = 8
EPOCH_PREPARED = 9


def register(  # noqa: PLR0913,PLR0917 — exact retained epoch intent
    control: Store,
    expected: dict,
    epoch: dict,
    secret_sha256: str,
    intent_sha256: str,
    native_sha256: str,
) -> dict:
    """Caller retained the full intent/bindings and revalidated current data."""
    journal.digest(intent_sha256)
    journal.digest(native_sha256)
    key = journal.identity(expected, epoch["cutover_operation_id"], secret_sha256)
    require(epoch["deployment_id"] == expected["deployment_id"], "epoch deployment differs")
    with journal.locked(control, expected):
        row = journal.selected(control, key)
        require(
            row is not None
            and row["step"] == EPOCH_INTENT - 1
            and row["receipts"][-1] == native_sha256,
            "native validation predecessor differs",
        )
        return control.one(
            "UPDATE organization_witness.cutover_operations SET step=8,receipts=%s "
            "WHERE deployment_id=%s AND operation_id=%s RETURNING to_jsonb(cutover_operations)",
            (Jsonb([*row["receipts"], intent_sha256]), key["deployment_id"], key["operation_id"]),
        )


def successor(before: dict, transition: dict) -> dict:
    require(
        transition["operation_id"] == before["operation_id"]
        and transition["revision"] == before["revision"],
        "epoch predecessor differs",
    )
    selected = transition["selection"]
    return dict(
        before,
        phase="prepared",
        revision=before["revision"] + 1,
        epoch=selected["epoch"],
        primary_id=selected["primary"],
        token_store_id=selected["token_store"],
        source_sha256=selected["source_sha256"],
        history_sha256=selected["history_sha256"],
        acceptance_sha256=selected["acceptance_sha256"],
    )


def observations(control: Store, original: dict, epoch: dict, principal: str) -> dict:
    deployment = epoch["deployment_id"]
    parents = control.rows(
        "SELECT to_jsonb(d) FROM organization_witness.deployments d "
        "WHERE deployment_id=%s FOR UPDATE",
        (deployment,),
    )
    require(len(parents) == 1, "exact epoch parent required")
    parent = parents[0][0]
    children = [
        row[0]
        for row in control.rows(
            "SELECT to_jsonb(a) FROM organization_witness.authorities a "
            "WHERE deployment_id=%s ORDER BY environment_id FOR UPDATE",
            (deployment,),
        )
    ]
    prepared = parent["phase"] == "prepared"
    planned = {row["environment_id"]: row for row in epoch["children"]}
    require(
        len(planned) == len(epoch["children"]) == len(children) == len(original["children"]),
        "complete epoch child inventory differs",
    )
    require(
        parent
        == (successor(original["parent"], epoch["parent"]) if prepared else original["parent"]),
        "epoch parent state differs",
    )
    for current, previous in zip(children, original["children"], strict=True):
        environment = previous["environment_id"]
        require(environment in planned, "epoch child is missing")
        expected = successor(previous, planned[environment]["transition"]) if prepared else previous
        require(current == expected, "epoch child state differs")
    bindings = preserved(control, original, epoch)
    require(bindings == original["bindings"], "retained epoch associations changed")
    checkpoints = check_checkpoints(control, original, epoch, principal, prepared=prepared)
    return {
        "parent": parent,
        "children": children,
        "checkpoints": checkpoints,
        "prepared": prepared,
    }


def preserved(control: Store, original: dict, epoch: dict) -> list:
    """Preserve unfinished observations; callers verify their exact binding state."""
    deployment = epoch["deployment_id"]
    require(
        not control.one(
            "SELECT EXISTS(SELECT FROM organization_witness.maintenance_slots "
            "WHERE deployment_id=%s AND pending) "
            "OR EXISTS(SELECT FROM organization_witness.deployment_slots "
            "WHERE deployment_id=%s AND pending) "
            "OR EXISTS(SELECT FROM organization_witness.slots s "
            "JOIN organization_witness.authorities a "
            "USING(environment_id) WHERE a.deployment_id=%s AND s.pending)",
            (deployment, deployment, deployment),
        ),
        "pending work remains during epoch preparation",
    )
    for key, query in {
        "parent_progress": (
            "SELECT to_jsonb(o) FROM organization_witness.deployment_store_observations o "
            "WHERE deployment_id=%s ORDER BY slot"
        ),
        "child_progress": (
            "SELECT to_jsonb(o) FROM organization_witness.store_observations o "
            "JOIN organization_witness.authorities a USING(environment_id) "
            "WHERE a.deployment_id=%s ORDER BY environment_id,slot"
        ),
    }.items():
        require(
            [row[0] for row in control.rows(query, (deployment,))] == original[key],
            "retained unfinished observations changed",
        )
    return [
        row[0]
        for row in control.rows(
            "SELECT to_jsonb(b) FROM organization_witness.deployment_children b "
            "WHERE deployment_id=%s ORDER BY environment_id,child_epoch",
            (deployment,),
        )
    ]


def check_checkpoints(
    control: Store, original: dict, epoch: dict, principal: str, *, prepared: bool
) -> list:
    planned = {row["environment_id"]: row for row in epoch["children"]}
    checkpoints = []
    for previous in original["parent_checkpoint"] + original["child_checkpoints"]:
        parent_scope = "deployment_id" in previous
        table = "deployment_store_checkpoints" if parent_scope else "store_checkpoints"
        scope = "deployment_id" if parent_scope else "environment_id"
        # Names come only from the fixed two alternatives above, never inputs.
        query = (
            f"SELECT to_jsonb(c) FROM organization_witness.{table} c WHERE {scope}=%s AND epoch=%s"  # noqa: S608
        )
        rows = control.rows(query, (previous[scope], previous["epoch"]))
        require(rows == [(previous,)], "original source checkpoint changed")
        transition = epoch["parent"] if parent_scope else planned[previous[scope]]["transition"]
        rows = control.rows(query, (previous[scope], transition["selection"]["epoch"]))
        if not prepared:
            require(not rows, "uncommitted new checkpoint already exists")
            continue
        require(len(rows) == 1, "prepared epoch checkpoint missing")
        row = rows[0][0]
        minimum = epoch["stores"]["primary"]["wal_position"]
        expected = {
            scope: previous[scope],
            "epoch": transition["selection"]["epoch"],
            "operation_id": transition["operation_id"],
            "prepared_revision": transition["revision"] + 1,
            "primary_id": transition["selection"]["primary"],
            "token_store_id": transition["selection"]["token_store"],
            "primary_incarnation": {
                k: v for k, v in epoch["stores"]["primary"].items() if k != "wal_position"
            },
            "token_incarnation": epoch["stores"]["token"],
            "principal": principal,
            "initial_wal": row["initial_wal"],
            "wal_position": row["initial_wal"],
        }
        require(row == expected and row["initial_wal"] >= minimum, "prepared checkpoint differs")
        checkpoints.append(row)
    require(
        len(original["parent_checkpoint"]) == 1
        and len(original["child_checkpoints"]) == len(epoch["children"]),
        "complete original checkpoints required",
    )
    return checkpoints


@contextmanager
def locked(  # noqa: PLR0913,PLR0917 — exact bound offline context
    control: Store,
    expected: dict,
    original: dict,
    epoch: dict,
    secret_sha256: str,
    intent_sha256: str,
    principal: str,
):
    journal.digest(intent_sha256)
    require(runtime.digest(original) == expected["state_sha256"], "original fence snapshot differs")
    require(epoch["deployment_id"] == expected["deployment_id"], "epoch deployment differs")
    restore.drained(control)
    recovery.checked_catalog(control)
    key = journal.identity(expected, epoch["cutover_operation_id"], secret_sha256)
    with control.connection.transaction():
        observed = observations(control, original, epoch, principal)
        rows = control.rows(
            "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c "
            "WHERE deployment_id=%s AND operation_id=%s FOR UPDATE",
            (key["deployment_id"], key["operation_id"]),
        )
        require(len(rows) == 1, "registered epoch intent required")
        row = rows[0][0]
        require(
            all(row[name] == value for name, value in key.items())
            and row["principal"] == control.one("SELECT session_user::text")
            and not row["completed"]
            and row["step"] in (EPOCH_INTENT, EPOCH_PREPARED)
            and len(row["receipts"]) == row["step"]
            and row["receipts"][7] == intent_sha256,
            "epoch journal differs",
        )
        for receipt in row["receipts"]:
            journal.digest(receipt)
        require(
            row["step"] != EPOCH_PREPARED or observed["prepared"],
            "completed preparation rolled back",
        )
        yield row, observed


def complete(  # noqa: PLR0913,PLR0917 — exact retained phase and result
    control: Store,
    expected: dict,
    original: dict,
    epoch: dict,
    secret_sha256: str,
    intent_sha256: str,
    principal: str,
    receipt_sha256: str,
) -> dict:
    """Caller rechecked current data/exclusions and durably retained the receipt."""
    journal.digest(receipt_sha256)
    with locked(control, expected, original, epoch, secret_sha256, intent_sha256, principal) as (
        row,
        observed,
    ):
        require(observed["prepared"], "epoch preparation remains uncommitted")
        if row["step"] == EPOCH_PREPARED:
            require(row["receipts"][-1] == receipt_sha256, "epoch completion receipt differs")
            return row
        return control.one(
            "UPDATE organization_witness.cutover_operations SET step=9,receipts=%s "
            "WHERE deployment_id=%s AND operation_id=%s RETURNING to_jsonb(cutover_operations)",
            (
                Jsonb([*row["receipts"], receipt_sha256]),
                epoch["deployment_id"],
                epoch["cutover_operation_id"],
            ),
        )
