"""Offline current-primary versus restored-primary inspection; never activates."""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import signal
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

import organization_recovery as recovery
import organization_recovery_runtime as runtime
from organization_recovery_store import RecoveryRefusedError, fence, require
from organization_restore_content import compare

if TYPE_CHECKING:
    from organization_recovery_store import Store

SQL_STORES = 3


def settings(raw: bytes) -> dict:
    import json  # noqa: PLC0415

    config = json.loads(raw)
    require(
        set(config) == {"version", "operation_id", "fence", "stores", "services"}
        and config["version"] == 1,
        "unknown restore inspection configuration",
    )
    expected = config["fence"]
    require(
        set(expected) == {"deployment_id", "operation_id", "revision", "state_sha256"},
        "exact restore fence required",
    )
    for value in (config["operation_id"], expected["deployment_id"], expected["operation_id"]):
        require(str(UUID(value)) == value and UUID(value).int != 0, "canonical nonnil ID required")
    require(
        type(expected["revision"]) is int
        and 0 < expected["revision"] < 2**63
        and re.fullmatch(r"[0-9a-f]{64}", expected["state_sha256"]),
        "exact restore revision/digest required",
    )
    require(len(config["stores"]) == SQL_STORES, "independent control, source and target required")
    recovery.inventory_settings(config, runtime_mode=True)
    return config


def drained(store: Store) -> None:
    store.check(excluded=True)
    require(
        not store.one(
            "SELECT EXISTS(SELECT FROM pg_subscription) OR EXISTS(SELECT FROM pg_extension "
            "WHERE extname NOT IN ('plpgsql','pgcrypto'))"
        ),
        "unqualified background store writer",
    )
    store.connection.execute("SELECT pg_stat_clear_snapshot()")
    require(
        not store.one(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE backend_type='client backend' "
            "AND pid<>pg_backend_pid())"
        ),
        "store has another live client",
    )


def observe(source: Store) -> dict:
    """Read actual identity/WAL; this alone grants no freshness or authority."""
    return source.one(
        "SELECT jsonb_build_object('cluster_id',system_identifier,'database_oid',"
        "(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),"
        "'database_name',current_database(),'started_us',"
        "(extract(epoch from pg_postmaster_start_time())*1000000)::bigint,"
        "'timeline',(pg_control_checkpoint()).timeline_id,"
        "'wal_position',(pg_current_wal_lsn()-'0/0'::pg_lsn)::numeric) FROM pg_control_system()"
    )


def current_source(snapshot: dict, source: Store) -> dict:
    observed = observe(source)
    incarnation = {k: v for k, v in observed.items() if k != "wal_position"}
    parent = snapshot["parent"]
    require(len(snapshot["parent_checkpoint"]) == 1, "current parent checkpoint required")
    require(
        len(snapshot["child_checkpoints"]) == len(snapshot["children"])
        and all(row["epoch"] is not None for row in snapshot["children"]),
        "complete selected child checkpoints required",
    )
    checkpoints = snapshot["parent_checkpoint"] + snapshot["child_checkpoints"]
    for row in checkpoints:
        require(
            row["primary_id"] == parent["primary_id"]
            and row["token_store_id"] == parent["token_store_id"]
            and row["primary_incarnation"] == incarnation
            and observed["wal_position"] >= row["wal_position"],
            "current primary incarnation or retained WAL floor differs",
        )
    epochs = {row["epoch"] for row in checkpoints}
    for row in snapshot["parent_progress"] + snapshot["child_progress"]:
        if row["epoch"] in epochs:
            require(
                observed["wal_position"] >= row["minimum_wal"]
                and (
                    row["finished_wal"] is None or observed["wal_position"] >= row["finished_wal"]
                ),
                "current primary precedes retained unfinished work",
            )
    return observed


def inspect(config: dict, stores: list[Store]) -> dict:
    control, source, target = stores
    identities = [store.identity["cluster"] for store in stores]
    require(len(set(identities)) == SQL_STORES, "restore stores must be independent clusters")
    for store in stores:
        drained(store)
        store.connection.execute(
            "SET statement_timeout='60s'; SET lock_timeout='5s'; "
            "SET idle_in_transaction_session_timeout='610s'; SET transaction_timeout='600s'"
        )
    recovery.checked_catalog(control)
    expected = config["fence"]
    require(
        not control.one(
            "SELECT EXISTS(SELECT FROM organization_witness.deployments WHERE deployment_id<>%s)",
            (expected["deployment_id"],),
        ),
        "shared deployment is not an offline restore target",
    )
    services = [recovery.stopped(name) for name in config["services"]]
    peer = config["stores"][0]["connection"].get("peer_user")
    if peer:
        require(
            all(recovery.user_id(state["User"]) != recovery.user_id(peer) for state in services),
            "old worker holds local control administrator identity",
        )
    with control.connection.transaction():
        fence(control, expected["deployment_id"])
        snapshot = runtime.state(control, expected["deployment_id"])
        require(
            snapshot["parent"]["operation_id"] == expected["operation_id"]
            and snapshot["parent"]["revision"] == expected["revision"]
            and runtime.digest(snapshot) == expected["state_sha256"],
            "restore fence changed",
        )
        before = current_source(snapshot, source)
        result = compare(source.connection, target.connection)
        after = current_source(snapshot, source)
        require(
            after == dict(before, wal_position=after["wal_position"])
            and after["wal_position"] >= before["wal_position"],
            "source changed during inspection",
        )
        require(
            runtime.state(control, expected["deployment_id"]) == snapshot,
            "restore authority changed",
        )
        for store in stores:
            drained(store)
        require(
            [recovery.stopped(name) for name in config["services"]] == services,
            "service state changed during inspection",
        )
    return {
        "version": 1,
        "operationId": config["operation_id"],
        "fence": expected,
        "configurationSha256": runtime.digest(config),
        "stores": [s.identity for s in stores],
        "sourceBefore": before,
        "sourceAfter": after,
        "content": result,
        "activationAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, "offline root inspection authority required")
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    signal.signal(
        signal.SIGALRM,
        lambda *_: (_ for _ in ()).throw(RecoveryRefusedError("restore inspection deadline")),
    )
    signal.alarm(600)
    config = settings(recovery.private_file(args.config))
    recovery.protected_path(args.output).mkdir(mode=0o700)
    recovery.sync_directory_entry(args.output)
    output = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(output, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with ExitStack() as stack:
            stores = [recovery.connect(stack, item) for item in config["stores"]]
            result = inspect(config, stores)
        recovery.retain(output, "comparison.json", result)
    finally:
        os.close(output)
    print("current primary content matches restored target; activation not authorized")


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 — do not disclose source data or credentials
        print("restore inspection unconfirmed; keep both stores fenced", file=sys.stderr)
        sys.exit(1)
