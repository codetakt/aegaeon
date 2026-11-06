"""Current-data and exclusion checks across the exact prepared epoch boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING

import organization_cutover_credentials as credentials
import organization_cutover_history as history
import organization_cutover_prepare as preparation
import organization_cutover_token as token
import organization_recovery as recovery
import organization_recovery_runtime as runtime
import organization_restore_inspect as restore
from organization_recovery_store import require

if TYPE_CHECKING:
    from organization_cutover_epochs import Work
    from organization_cutover_validation import Context


def follows(actual: dict, expected: dict) -> None:
    require(
        actual == dict(expected, wal_position=actual["wal_position"])
        and actual["wal_position"] >= expected["wal_position"],
        "current epoch physical store or WAL differs",
    )


def exclusions(config: dict, context: Context, stores: list, original: dict) -> list:
    require(
        len({store.identity["cluster"] for store in stores}) == restore.SQL_STORES,
        "independent epoch stores required",
    )
    for store in stores:
        restore.drained(store)
        store.connection.execute(
            "SET statement_timeout='60s'; SET lock_timeout='5s'; "
            "SET idle_in_transaction_session_timeout='610s'; SET transaction_timeout='600s'"
        )
    for i, store in enumerate(context.stores):
        require(
            credentials.status(store, context.plan.sql(i)) == "replaced-disabled",
            "epoch credentials remain enabled",
        )
    context.old.check(excluded=True)
    current = str(context.old.call("CLIENT", "ID"))
    require([row["id"] for row in context.old.clients()] == [current], "old token client remains")
    checkpoints = original["parent_checkpoint"] + original["child_checkpoints"]
    require(
        len(original["parent_checkpoint"]) == 1
        and len(original["child_checkpoints"]) == len(original["children"])
        and all(row["token_incarnation"] == context.old.identity for row in checkpoints),
        "retired token differs from original authority",
    )
    require(
        token.check(context.new, context.old.identity["run_id"], context.plan.redis()),
        "fresh token credential missing",
    )
    services = [recovery.stopped(name) for name in config["services"]]
    peer = config["stores"][0]["connection"].get("peer_user")
    if peer:
        require(
            all(recovery.user_id(state["User"]) != recovery.user_id(peer) for state in services),
            "worker holds control administrator identity",
        )
    require(
        not stores[0].one(
            "SELECT EXISTS(SELECT FROM organization_witness.deployments WHERE deployment_id<>%s)",
            (config["fence"]["deployment_id"],),
        ),
        "shared deployment cannot be cut over offline",
    )
    return services


def inspect(work: Work, *, complete: bool = False) -> dict:
    config = work.config["inspection"]
    context = work.context
    control, source, target = work.stores
    services = exclusions(config, context, work.stores, work.original)
    with work.locked() as (row, observed):
        before = restore.current_source(work.original, source)
        content = restore.compare(source.connection, target.connection)
        after = restore.current_source(work.original, source)
        follows(after, before)
        preparation.comparison(
            work.directory,
            context.descriptor,
            {
                "version": 1,
                "operationId": config["operation_id"],
                "fence": context.expected,
                "configurationSha256": runtime.digest(config),
                "stores": [store.identity for store in work.stores],
                "sourceBefore": before,
                "sourceAfter": after,
                "content": content,
                "activationAuthorized": False,
            },
        )
        primary = restore.observe(target)
        follows(primary, work.epoch["stores"]["primary"])
        follows(restore.observe(control), work.epoch["stores"]["control"])
        require(
            context.new.identity == work.epoch["stores"]["token"], "epoch token identity changed"
        )
        for checkpoint in observed["checkpoints"]:
            require(
                primary["wal_position"] >= checkpoint["wal_position"],
                "destination precedes prepared checkpoint",
            )
        for result in work.native["results"]:
            require(
                history.compare(control, target, result["native"]["history"]["history"])
                == result["permanentFacts"],
                "epoch permanent facts changed",
            )
        require(
            exclusions(config, context, work.stores, work.original) == services,
            "epoch service custody changed",
        )
        if complete:
            require(observed["prepared"], "epoch remains unprepared")
        return {"step": row["step"], "observed": observed}


def native_receipt(work: Work, observed: dict) -> dict:
    parent = dict(observed["parent"], pending=0)
    children = [dict(row, pending=0) for row in observed["children"]]
    checkpoints = observed["checkpoints"]
    return {
        "version": 1,
        "intentSha256": work.intent_sha256,
        "selection": {"parent": parent, "children": children},
        "parentProgress": {"checkpoint": checkpoints[0]},
        "children": [
            {"state": row, "progress": {"checkpoint": progress}}
            for row, progress in zip(children, checkpoints[1:], strict=True)
        ],
        "activationAuthorized": False,
        "supplierQualified": False,
    }
