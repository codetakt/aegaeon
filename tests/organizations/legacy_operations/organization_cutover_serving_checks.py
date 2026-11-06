"""Current serving suppliers and old-writer exclusion, without source overwrite."""

from __future__ import annotations

from typing import TYPE_CHECKING

import organization_cutover_epoch_checks as epochs
import organization_cutover_serving_credentials as credentials
import organization_recovery as recovery
import organization_restore_inspect as restore
from organization_recovery_store import require

if TYPE_CHECKING:
    from organization_cutover_serving import Work

MAX_OPERATIONS = 65536


def names(work: Work) -> list[set[str]]:
    return [{work.context.principals[key]["new"]} for key in ("control_runtime", "primary_runtime")]


def exclusions(work: Work, *, enabled: bool) -> dict:
    context = work.context
    for index, selected in enumerate(names(work)):
        actual = credentials.sql_observed(context.stores[index], context.plan.sql(index), selected)
        require(actual == (selected if enabled else set()), "selected SQL serving state differs")
    require(
        credentials.token_observed(
            context.new, context.old.identity["run_id"], context.plan.redis()
        )
        == enabled,
        "selected token serving state differs",
    )
    restore.drained(work.stores[1])
    context.old.check(excluded=True)
    current = str(context.old.call("CLIENT", "ID"))
    require(
        [row["id"] for row in context.old.clients()] == [current], "retired token client remains"
    )
    services = [recovery.stopped(unit) for unit in work.config["inspection"]["services"]]
    return {
        "oldServices": services,
        "selectedRuntimeEnabled": enabled,
        "retiredCredentialsExcluded": True,
    }


def current(work: Work, *, enabled: bool) -> dict:
    excluded = exclusions(work, enabled=enabled)
    with work.locked() as (row, observed):
        primary = restore.observe(work.stores[2])
        epochs.follows(primary, work.epoch["stores"]["primary"])
        epochs.follows(restore.observe(work.stores[0]), work.epoch["stores"]["control"])
        require(
            work.context.new.identity == work.epoch["stores"]["token"],
            "serving token incarnation changed",
        )
        require(
            all(
                primary["wal_position"] >= checkpoint["wal_position"]
                for checkpoint in observed["checkpoints"]
            ),
            "serving primary precedes retained highwater",
        )
        return {"step": row["step"], "observed": observed, "exclusions": excluded}


def reserve_closure(work: Work, intent: dict) -> None:
    with work.locked() as (_, observed):
        require(observed["active"], "active inventory required before first start")
        for index, (state, fence) in enumerate(
            zip([observed["parent"], *observed["children"]], intent["fences"], strict=True)
        ):
            require(state["revision"] < 2**63 - 1, "closure fence revision exhausted")
            table, scope, operation = (
                ("deployment_operations", "deployment_id", "operation_id")
                if index == 0
                else ("operations", "environment_id", "id")
            )
            identifier = state[scope]
            count, exists = work.stores[0].rows(
                f"SELECT count(*),COALESCE(bool_or({operation}=%s),false) "  # noqa: S608 — fixed two table/column alternatives
                f"FROM organization_witness.{table} WHERE {scope}=%s",
                (fence["operation_id"], identifier),
            )[0]
            require(
                count < MAX_OPERATIONS and not exists, "fresh closure operation capacity required"
            )
