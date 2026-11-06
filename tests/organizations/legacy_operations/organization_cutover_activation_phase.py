"""Exact prepared-to-active offline selection; serving credentials stay disabled."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from typing import TYPE_CHECKING

import organization_cutover_epoch_inputs as inputs
import organization_cutover_journal as journal
import organization_cutover_phase as phase
import organization_recovery as recovery
import organization_recovery_runtime as runtime
import organization_restore_inspect as restore
from organization_recovery_store import require
from psycopg.types.json import Jsonb

if TYPE_CHECKING:
    from organization_cutover_activation import Work

ACTIVATION_INTENT = 12
ACTIVATED = 13
PUBLISHED = 11
STEPS = (PUBLISHED, ACTIVATION_INTENT, ACTIVATED)


def observations(work: Work) -> dict:
    control, original, epoch = work.stores[0], work.original, work.epoch
    parents = control.rows(
        "SELECT to_jsonb(d) FROM organization_witness.deployments d "
        "WHERE deployment_id=%s FOR UPDATE",
        (epoch["deployment_id"],),
    )
    require(len(parents) == 1, "exact activation parent required")
    parent = parents[0][0]
    children = [
        row[0]
        for row in control.rows(
            "SELECT to_jsonb(a) FROM organization_witness.authorities a "
            "WHERE deployment_id=%s ORDER BY environment_id FOR UPDATE",
            (epoch["deployment_id"],),
        )
    ]
    active = parent["phase"] == "active"
    require(
        len(children) == len(original["children"]) == len(epoch["children"]),
        "complete activation child inventory differs",
    )
    before = [original["parent"], *original["children"]]
    transitions = [epoch["parent"], *[row["transition"] for row in epoch["children"]]]
    for current, previous, transition in zip([parent, *children], before, transitions, strict=True):
        expected = phase.successor(previous, transition)
        if active:
            expected = dict(expected, phase="active", revision=expected["revision"] + 1)
        require(current == expected, "complete prepared or active selection required")
    bindings = phase.preserved(control, original, epoch)
    selected = []
    if active:
        for child in epoch["children"]:
            expected = {
                "environment_id": child["environment_id"],
                "child_epoch": child["transition"]["selection"]["epoch"],
                "deployment_id": epoch["deployment_id"],
                "deployment_epoch": epoch["parent"]["selection"]["epoch"],
                "principal": work.context.principals["control_maintenance"]["new"],
            }
            rows = [
                row
                for row in bindings
                if all(row.get(key) == value for key, value in expected.items())
            ]
            require(
                len(rows) == 1 and set(rows[0]) == {*expected, "bound_at"},
                "selected activation binding differs",
            )
            require(
                datetime.fromisoformat(rows[0]["bound_at"]).tzinfo is not None,
                "activation binding timestamp missing",
            )
            selected.append(rows[0])
    expected = sorted(
        [*original["bindings"], *selected],
        key=lambda row: (row["environment_id"], row["child_epoch"]),
    )
    require(bindings == expected, "historical or selected activation bindings differ")
    checkpoints = phase.check_checkpoints(
        control,
        original,
        epoch,
        work.context.principals["control_maintenance"]["new"],
        prepared=True,
    )
    return {
        "parent": parent,
        "children": children,
        "checkpoints": checkpoints,
        "bindings": selected,
        "prepared": True,
        "active": active,
    }


@contextmanager
def locked(work: Work):
    control, context = work.stores[0], work.context
    require(
        runtime.digest(work.original) == context.expected["state_sha256"], "original fence differs"
    )
    restore.drained(control)
    recovery.checked_catalog(control)
    key = journal.identity(
        context.expected, work.epoch["cutover_operation_id"], context.plan.sha256
    )
    with control.connection.transaction():
        observed = observations(work)
        rows = control.rows(
            "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c "
            "WHERE deployment_id=%s AND operation_id=%s FOR UPDATE",
            (key["deployment_id"], key["operation_id"]),
        )
        require(len(rows) == 1, "registered activation predecessor required")
        row = rows[0][0]
        require(
            all(row[name] == value for name, value in key.items())
            and row["principal"] == control.one("SELECT session_user::text")
            and not row["completed"]
            and row["step"] in STEPS
            and len(row["receipts"]) == row["step"]
            and row["receipts"][6] == work.native_sha256
            and row["receipts"][7] == work.intent_sha256
            and row["receipts"][9] == work.manifest_sha256,
            "activation journal differs",
        )
        for digest in row["receipts"]:
            journal.digest(digest)
        if row["step"] >= ACTIVATION_INTENT:
            _, digest = inputs.read(work.directory, "activation.json")
            require(digest == row["receipts"][11], "registered activation intent differs")
        require(
            row["step"] != PUBLISHED or not observed["active"], "unregistered activation detected"
        )
        require(row["step"] != ACTIVATED or observed["active"], "completed activation rolled back")
        yield row, observed


def advance(work: Work, step: int, digest: str) -> dict:
    require(step in (ACTIVATION_INTENT, ACTIVATED), "invalid activation step")
    journal.digest(digest)
    with locked(work) as (row, observed):
        require(step != ACTIVATED or observed["active"], "activation remains uncommitted")
        if row["step"] >= step:
            require(row["receipts"][step - 1] == digest, "activation replay differs")
            return row
        require(row["step"] == step - 1, "activation predecessor missing")
        return work.stores[0].one(
            "UPDATE organization_witness.cutover_operations SET step=%s,receipts=%s "
            "WHERE deployment_id=%s AND operation_id=%s RETURNING to_jsonb(cutover_operations)",
            (
                step,
                Jsonb([*row["receipts"], digest]),
                work.epoch["deployment_id"],
                work.epoch["cutover_operation_id"],
            ),
        )
