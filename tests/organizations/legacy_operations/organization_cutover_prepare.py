"""Compose offline cutover preparation; never activate an epoch or worker."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import signal
import stat
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING

import organization_cutover_credentials as credentials
import organization_cutover_journal as journal
import organization_cutover_plan as plans
import organization_cutover_token as token
import organization_recovery as recovery
import organization_recovery_runtime as runtime
import organization_restore_inspect as restore
from organization_recovery_redis import RedisStore
from organization_recovery_resp import Resp
from organization_recovery_store import RecoveryRefusedError, require

if TYPE_CHECKING:
    from organization_recovery_store import Store


def settings(raw: bytes) -> dict:
    config = json.loads(raw)
    require(
        set(config) == {"inspection", "names", "redis", "preparation"},
        "exact cutover configuration required",
    )
    inspection = restore.settings(json.dumps(config["inspection"]))
    preparation = config["preparation"]
    require(
        set(preparation) == {"version", "retired_token", "destination_token"}
        and preparation["version"] == 1,
        "unknown cutover preparation version",
    )
    expected = inspection["fence"]
    for name in ["retired_token", "destination_token"]:
        runtime.settings(
            {
                "version": runtime.VERSION,
                "runtime": {
                    "deployment_id": expected["deployment_id"],
                    "recovery_id": inspection["operation_id"],
                    "fence_operation_id": expected["operation_id"],
                    "fence_revision": expected["revision"],
                    "state_sha256": expected["state_sha256"],
                },
                "stores": inspection["stores"][:2],
                "services": inspection["services"],
                "token": preparation[name],
            }
        )
    require(
        preparation["destination_token"]["old_logins"] == ["default"],
        "fresh token inventory required",
    )
    require(
        type(config["names"]) is list
        and len(config["names"]) == plans.STORE_COUNT
        and all(
            type(value) is dict and 0 < len(value) <= credentials.MAX_ROLES
            for value in config["names"]
        ),
        "bounded complete SQL mappings required",
    )
    require(set(config["redis"]) == {"name", "commands"}, "explicit new token profile required")
    return config


def connect_token(stack: ExitStack, value: dict) -> RedisStore:
    configured = value["connection"]
    link = Resp(
        configured["host"],
        configured["port"],
        recovery.private_file(configured["ca_file"]).decode(),
        configured["user"],
        recovery.private_file(configured["password_file"]).decode().rstrip("\n"),
    )
    stack.callback(link.close)
    return RedisStore(link, value["identity"], configured["user"], value["old_logins"])


def retired(control: Store, expected: dict, old: RedisStore) -> None:
    old.check(excluded=True)
    current = str(old.call("CLIENT", "ID"))
    require([row["id"] for row in old.clients()] == [current], "retired token client remains")
    with journal.locked(control, expected):
        snapshot = runtime.state(control, expected["deployment_id"])
        checkpoints = snapshot["parent_checkpoint"] + snapshot["child_checkpoints"]
        require(
            len(snapshot["parent_checkpoint"]) == 1
            and len(snapshot["child_checkpoints"]) == len(snapshot["children"])
            and all(row["token_incarnation"] == old.identity for row in checkpoints),
            "retired token differs from independently retained checkpoint",
        )


def comparison(directory: Path, descriptor: int, observed: dict) -> str:
    path = directory / "comparison.json"
    if not path.exists():
        return recovery.retain(descriptor, "comparison.json", observed)
    raw = recovery.private_file(path, plans.MAX_PLAN)
    previous = json.loads(raw)
    for field in [
        "version",
        "operationId",
        "fence",
        "configurationSha256",
        "stores",
        "content",
        "activationAuthorized",
    ]:
        require(previous[field] == observed[field], "retained cutover comparison differs")
    for field in ["sourceBefore", "sourceAfter"]:
        old, new = previous[field], observed[field]
        require(
            new == dict(old, wal_position=new["wal_position"])
            and new["wal_position"] >= old["wal_position"],
            "current source precedes retained comparison",
        )
    return hashlib.sha256(raw).hexdigest()


def prepare(config: dict, stores: list, old: RedisStore, new: RedisStore, directory: Path) -> dict:  # noqa: PLR0912,PLR0915 — ordered retained saga
    control, _, destination = stores
    inspection = config["inspection"]
    expected, operation = inspection["fence"], inspection["operation_id"]
    retired(control, expected, old)
    observed = restore.inspect(inspection, stores)
    with journal.locked(control, expected):
        rows = control.rows(
            "SELECT plan_sha256 FROM organization_witness.cutover_operations "
            "WHERE deployment_id=%s AND operation_id=%s",
            (expected["deployment_id"], operation),
        )
    plan = (
        plans.load(config, directory, rows[0][0])
        if rows
        else plans.create(config, [control, destination], directory)
    )
    token.check(new, old.identity["run_id"], plan.redis())
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        receipt = comparison(directory, descriptor, observed)
        state = journal.inspect(control, expected, operation, plan.sha256)

        def advance(predecessor: str, digest: str) -> dict:
            return journal.advance(control, expected, operation, plan.sha256, predecessor, digest)

        if journal.PREPARATION[state["step"]] == "registered":
            state = advance("registered", receipt)
        if journal.PREPARATION[state["step"]] == "content-checked":
            state = advance("content-checked", plan.sha256)
        if journal.PREPARATION[state["step"]] == "sql-intent":
            with journal.locked(control, expected):
                for index, store in enumerate([control, destination]):
                    replacements = plan.sql(index)
                    if credentials.status(store, replacements) == "excluded":
                        credentials.rotate(store, replacements)
                    require(
                        credentials.status(store, replacements) == "replaced-disabled",
                        "SQL preparation incomplete",
                    )
            state = advance("sql-intent", plan.sha256)
        for index, store in enumerate([control, destination]):
            require(
                credentials.status(store, plan.sql(index)) == "replaced-disabled",
                "prepared SQL credential changed",
            )
        if journal.PREPARATION[state["step"]] == "sql-prepared":
            state = advance("sql-prepared", plan.sha256)
        if journal.PREPARATION[state["step"]] == "token-intent":
            with journal.locked(control, expected):
                result = token.prepare(new, old.identity["run_id"], plan.redis())
            state = advance("token-intent", runtime.digest(result))
        require(
            journal.PREPARATION[state["step"]] == "token-prepared",
            "cutover preparation is outside this entry",
        )
        retired(control, expected, old)
        require(
            token.check(new, old.identity["run_id"], plan.redis()),
            "prepared token credential missing",
        )
        restore.inspect(inspection, stores)
        return {
            "version": 1,
            "operationId": operation,
            "planSha256": plan.sha256,
            "step": state["step"],
            "activationAuthorized": False,
        }
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, "offline root preparation required")
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    signal.signal(
        signal.SIGALRM,
        lambda *_: (_ for _ in ()).throw(RecoveryRefusedError("preparation deadline")),
    )
    signal.alarm(600)
    config = settings(recovery.private_file(args.config))
    recovery.protected_path(args.directory).mkdir(mode=0o700, exist_ok=True)
    recovery.sync_directory_entry(args.directory)
    descriptor = plans.directory(args.directory)
    os.close(descriptor)
    lock = os.open(
        args.directory / ".coordinator-lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(lock)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o077
            and info.st_nlink == 1,
            "private coordinator lock required",
        )
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with ExitStack() as stack:
            stores = [recovery.connect(stack, value) for value in config["inspection"]["stores"]]
            old = connect_token(stack, config["preparation"]["retired_token"])
            new = connect_token(stack, config["preparation"]["destination_token"])
            result = prepare(config, stores, old, new, args.directory)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 — no database/secret/configuration disclosure
        print(
            "cutover preparation unconfirmed; retain exact plan and keep all stores fenced",
            file=sys.stderr,
        )
        sys.exit(1)
