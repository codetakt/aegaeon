"""Retained serving state permits progress; aborted closure never erases it."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import organization_cutover_activation as activation
import organization_cutover_epoch_inputs as inputs
import organization_cutover_journal as journal
import organization_recovery as recovery
from organization_recovery_store import require
from psycopg.types.json import Jsonb

if TYPE_CHECKING:
    from organization_cutover_serving import Work
    from organization_recovery_store import Store

ACTIVATED, START_INTENT, STARTED, COMPLETE = 13, 14, 15, 16
STEPS = (ACTIVATED, START_INTENT, STARTED, COMPLETE)


def predecessor(
    control: Store, expected: dict, operation: str, *, steps: tuple[int, ...] = STEPS
) -> dict:
    recovery.checked_catalog(control)
    rows = control.rows(
        "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c "
        "WHERE deployment_id=%s AND operation_id=%s",
        (expected["deployment_id"], operation),
    )
    require(len(rows) == 1, "registered serving predecessor required")
    row = rows[0][0]
    key = journal.identity(expected, operation, row["plan_sha256"])
    require(
        all(row[name] == value for name, value in key.items())
        and row["principal"] == control.one("SELECT session_user::text")
        and row["step"] in steps
        and len(row["receipts"]) == row["step"]
        and row["completed"] == (row["step"] == COMPLETE),
        "serving journal differs",
    )
    for digest in row["receipts"]:
        journal.digest(digest)
    return row


def binding_rows(rows: list) -> list:
    value = {"selection": {"bindings": rows}}
    return activation.canonical_receipt(value)["selection"]["bindings"]


def observations(work: Work, row: dict) -> dict:  # noqa: PLR0915 — complete current selection and monotone checkpoints
    control, epoch = work.stores[0], work.epoch
    activated, digest = inputs.read(work.directory, "epoch-activated.json")
    require(digest == row["receipts"][12], "registered activation completion differs")
    selection = activated["native"]["selection"]
    previous = [selection["parent"], *selection["children"]]
    expected = [{k: v for k, v in item.items() if k != "pending"} for item in previous]
    actual = [
        control.one(
            "SELECT to_jsonb(d) FROM organization_witness.deployments d "
            "WHERE deployment_id=%s FOR UPDATE",
            (epoch["deployment_id"],),
        )
    ]
    actual += [
        v[0]
        for v in control.rows(
            "SELECT to_jsonb(a) FROM organization_witness.authorities a "
            "WHERE deployment_id=%s ORDER BY environment_id FOR UPDATE",
            (epoch["deployment_id"],),
        )
    ]
    require(len(actual) == len(expected), "complete serving child inventory differs")
    fenced = actual[0]["phase"] == "fenced"
    if row["step"] >= START_INTENT:
        intent, digest = inputs.read(work.directory, "serving-intent.json")
        require(digest == row["receipts"][13], "registered serving intent differs")
        require(len(intent["fences"]) == len(expected), "complete closure fence inventory required")
        if fenced:
            expected = [
                dict(
                    item,
                    phase="fenced",
                    operation_id=fence["operation_id"],
                    revision=item["revision"] + 1,
                )
                for item, fence in zip(expected, intent["fences"], strict=True)
            ]
    require(
        actual == expected and (not fenced or row["step"] >= START_INTENT),
        "current serving selection differs",
    )
    require(not row["aborted"] or fenced, "completed abort is not fenced")
    require(not row["completed"] or not fenced, "completed serving selection is fenced")
    expected_bindings = sorted(
        [*work.original["bindings"], *selection["bindings"]],
        key=lambda item: (item["environment_id"], item["child_epoch"]),
    )
    bindings = [
        v[0]
        for v in control.rows(
            "SELECT to_jsonb(b) FROM organization_witness.deployment_children b "
            "WHERE deployment_id=%s ORDER BY environment_id,child_epoch",
            (epoch["deployment_id"],),
        )
    ]
    require(
        binding_rows(bindings) == binding_rows(expected_bindings),
        "serving association history differs",
    )
    checkpoints = []
    initial = [selection["parentCheckpoint"], *selection["childCheckpoints"]]
    for old, archive in zip(
        work.original["parent_checkpoint"] + work.original["child_checkpoints"],
        initial,
        strict=True,
    ):
        parent = "deployment_id" in archive
        table, scope = (
            ("deployment_store_checkpoints", "deployment_id")
            if parent
            else ("store_checkpoints", "environment_id")
        )
        query = (
            f"SELECT to_jsonb(c) FROM organization_witness.{table} c WHERE {scope}=%s AND epoch=%s"  # noqa: S608 — fixed table and column alternatives
        )
        require(
            control.rows(query, (old[scope], old["epoch"])) == [(old,)],
            "original checkpoint changed during serving",
        )
        current = control.one(query, (archive[scope], archive["epoch"]))
        require(
            current == dict(archive, wal_position=current["wal_position"])
            and current["wal_position"] >= archive["wal_position"],
            "serving checkpoint decreased or changed",
        )
        checkpoints.append(current)
    return {
        "parent": actual[0],
        "children": actual[1:],
        "checkpoints": checkpoints,
        "initial": initial,
        "bindings": bindings,
        "prepared": True,
        "active": not fenced,
    }


@contextmanager
def locked(work: Work):
    control = work.stores[0]
    with control.connection.transaction():
        control.rows(
            "SELECT deployment_id FROM organization_witness.deployments "
            "WHERE deployment_id=%s FOR UPDATE",
            (work.epoch["deployment_id"],),
        )
        control.rows(
            "SELECT operation_id FROM organization_witness.cutover_operations "
            "WHERE deployment_id=%s AND operation_id=%s FOR UPDATE",
            (work.epoch["deployment_id"], work.epoch["cutover_operation_id"]),
        )
        row = predecessor(control, work.context.expected, work.epoch["cutover_operation_id"])
        require(
            row["plan_sha256"] == work.context.plan.sha256
            and row["receipts"][6] == work.native_sha256
            and row["receipts"][7] == work.intent_sha256
            and row["receipts"][9] == work.manifest_sha256,
            "serving input chain differs",
        )
        yield row, observations(work, row)


def advance(work: Work, step: int, digest: str) -> dict:
    require(step in (START_INTENT, STARTED, COMPLETE), "invalid serving step")
    journal.digest(digest)
    with locked(work) as (row, observed):
        require(not row["aborted"] and observed["active"], "serving operation already closed")
        if row["step"] >= step:
            require(row["receipts"][step - 1] == digest, "serving replay differs")
            return row
        require(row["step"] == step - 1, "serving predecessor missing")
        return work.stores[0].one(
            "UPDATE organization_witness.cutover_operations SET step=%s,receipts=%s,completed=%s "
            "WHERE deployment_id=%s AND operation_id=%s RETURNING to_jsonb(cutover_operations)",
            (
                step,
                Jsonb([*row["receipts"], digest]),
                step == COMPLETE,
                work.epoch["deployment_id"],
                work.epoch["cutover_operation_id"],
            ),
        )
