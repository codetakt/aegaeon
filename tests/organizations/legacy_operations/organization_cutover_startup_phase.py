"""Offline prepared-only publication transitions; no activation authority."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import organization_cutover_journal as journal
import organization_cutover_phase as phase
import organization_recovery as recovery
import organization_recovery_runtime as runtime
import organization_restore_inspect as restore
from organization_recovery_store import require
from psycopg.types.json import Jsonb

if TYPE_CHECKING:
    from organization_cutover_startup import Work

STARTUP_INTENT = 10
STARTUP_PUBLISHED = 11
STEPS = (phase.EPOCH_PREPARED, STARTUP_INTENT, STARTUP_PUBLISHED)


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
        observed = phase.observations(
            control, work.original, work.epoch, context.principals["control_maintenance"]["new"]
        )
        require(observed["prepared"], "startup publication requires complete prepared authority")
        rows = control.rows(
            "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c "
            "WHERE deployment_id=%s AND operation_id=%s FOR UPDATE",
            (key["deployment_id"], key["operation_id"]),
        )
        require(len(rows) == 1, "registered cutover required")
        row = rows[0][0]
        require(
            all(row[name] == value for name, value in key.items())
            and row["principal"] == control.one("SELECT session_user::text")
            and not row["completed"]
            and row["step"] in STEPS
            and len(row["receipts"]) == row["step"]
            and row["receipts"][6] == work.native_sha256
            and row["receipts"][7] == work.intent_sha256,
            "startup predecessor differs",
        )
        for digest in row["receipts"]:
            journal.digest(digest)
        require(
            row["step"] == phase.EPOCH_PREPARED or row["receipts"][9] == work.manifest_sha256,
            "startup manifest receipt differs",
        )
        yield row, observed


def advance(work: Work, step: int, digest: str) -> dict:
    require(step in (STARTUP_INTENT, STARTUP_PUBLISHED), "invalid publication step")
    journal.digest(digest)
    with locked(work) as (row, _):
        if row["step"] >= step:
            require(row["receipts"][step - 1] == digest, "publication replay receipt differs")
            return row
        require(row["step"] == step - 1, "publication predecessor missing")
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
