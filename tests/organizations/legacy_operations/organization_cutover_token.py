"""Prepare an empty replacement Redis store; never enable runtime credentials."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from organization_recovery_redis import DATABASE_COUNT, WORKER_COMMANDS, RedisStore, pairs
from organization_recovery_store import require

MIN_SECRET_BYTES = 32
MAX_SECRET_BYTES = 1024


@dataclass(frozen=True, repr=False)
class Credential:
    name: str
    password_sha256: str = field(repr=False)
    commands: frozenset[str]


def credential(name: str, password: bytes, commands: set[str]) -> Credential:
    require(
        re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name) and name != "default",
        "explicit fresh Redis identity required",
    )
    require(
        type(password) is bytes
        and MIN_SECRET_BYTES <= len(password) <= MAX_SECRET_BYTES
        and b"\0" not in password,
        "bounded Redis secret required",
    )
    require(
        commands and commands <= WORKER_COMMANDS,
        "explicit restricted Redis command profile required",
    )
    # Redis ACL #<hash> requires SHA-256 hex of a high-entropy machine secret:
    # https://redis.io/docs/latest/commands/acl-setuser/
    # This retained fixture is not application password storage or production code.
    return Credential(name, hashlib.sha256(password).hexdigest(), frozenset(commands))


def profile(store: RedisStore, value: Credential, *, enabled: bool = False) -> None:
    user = pairs(store.call("ACL", "GETUSER", value.name))
    commands = user["commands"].split()
    require(
        set(user["flags"]) == {"on" if enabled else "off", "sanitize-payload"}
        and user["passwords"] == [value.password_sha256]
        and not user["selectors"]
        and user["keys"] == "~*"
        and user["channels"] == ""
        and commands
        and commands[0] == "-@all"
        and set(commands[1:]) == {"+" + command for command in value.commands},
        "prepared Redis credential profile differs",
    )


def empty(store: RedisStore) -> None:
    # Every logical database belongs to this dedicated instance. The source of
    # old roots must not be accepted merely because the selected DB is empty.
    for index in range(DATABASE_COUNT):
        store.call("SELECT", str(index))
        require(store.call("DBSIZE") == 0, "replacement Redis contains retained data")
    store.call("SELECT", str(store.identity["database"]))
    current = str(store.call("CLIENT", "ID"))
    require(
        [row["id"] for row in store.clients()] == [current],
        "replacement Redis has another live client",
    )


def check(store: RedisStore, old_run_id: str, value: Credential) -> bool:
    require(
        re.fullmatch(r"[0-9a-f]{40}", old_run_id) and store.identity["run_id"] != old_run_id,
        "replacement Redis must have a new incarnation",
    )
    require(
        value.name not in ("default", store.administrator), "separate new Redis principal required"
    )
    users = set(store.call("ACL", "USERS"))
    exists = value.name in users
    expected = {store.administrator, "default", *([value.name] if exists else [])}
    require(users == expected, "replacement Redis login inventory differs")
    inspected = RedisStore(
        store.connection,
        store.identity,
        store.administrator,
        ["default", *([value.name] if exists else [])],
    )
    inspected.check()
    default = pairs(store.call("ACL", "GETUSER", "default"))
    require(
        set(default["flags"]) == {"off", "sanitize-payload"}
        and not default["passwords"]
        and default["commands"] == "-@all"
        and default["keys"] == ""
        and default["channels"] == ""
        and not default["selectors"],
        "default Redis credential must remain excluded",
    )
    if exists:
        profile(store, value)
    empty(store)
    return exists


def prepare(store: RedisStore, old_run_id: str, value: Credential) -> dict:
    exists = check(store, old_run_id, value)
    if not exists:
        require(
            store.call(
                "ACL",
                "SETUSER",
                value.name,
                "reset",
                "off",
                "#" + value.password_sha256,
                "~*",
                *("+" + command for command in sorted(value.commands)),
            )
            == "OK",
            "Redis credential preparation unconfirmed",
        )
    # A repeated explicit operation confirms persistence of the exact retained
    # profile after a lost ACK; it never creates a second password or enables it.
    require(store.call("ACL", "SAVE") == "OK", "prepared Redis ACL persistence unconfirmed")
    require(check(store, old_run_id, value), "prepared Redis credential missing")
    return {
        "identity": store.identity,
        "principal": value.name,
        "commands": sorted(value.commands),
        "empty": True,
        "enabled": False,
        "activationAuthorized": False,
    }


def validation_enable(store: RedisStore, old_run_id: str, value: Credential) -> None:
    """Only after the root caller retains intent; authority remains fenced."""
    require(check(store, old_run_id, value), "prepared token credential required")
    require(store.call("ACL", "SETUSER", value.name, "on") == "OK", "token login unconfirmed")
    require(store.call("ACL", "SAVE") == "OK", "token validation persistence unconfirmed")
    profile(store, value, enabled=True)


def validation_disable(store: RedisStore, old_run_id: str, value: Credential) -> dict:
    """Exclude login before closing real connections; safe after an uncertain reply."""
    inspected = RedisStore(
        store.connection, store.identity, store.administrator, ["default", value.name]
    )
    inspected.check()
    active = "on" in pairs(store.call("ACL", "GETUSER", value.name))["flags"]
    profile(store, value, enabled=active)
    require(store.call("ACL", "SETUSER", value.name, "off") == "OK", "token exclusion unconfirmed")
    require(store.call("ACL", "SAVE") == "OK", "token exclusion persistence unconfirmed")
    for client in store.clients():
        if client["user"] == value.name:
            require(
                store.call("CLIENT", "KILL", "ID", client["id"]) == 1,
                "token validation connection remains",
            )
    require(check(store, old_run_id, value), "token validation cleanup differs")
    return {
        "identity": store.identity,
        "principal": value.name,
        "disabled": True,
        "remainingClients": 0,
        "empty": True,
        "activationAuthorized": False,
    }
