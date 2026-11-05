"""Exact serving identities; closure preserves data and never grants maintenance."""

from __future__ import annotations

from dataclasses import replace

import organization_cutover_credentials as credentials
import organization_cutover_token as token
from organization_recovery_redis import RedisStore, pairs
from organization_recovery_store import Store, require
from psycopg import sql


def sql_observed(store: Store, replacements: list, names: set[str]) -> set[str]:
    require(
        names and names <= {item.new for item in replacements}, "selected serving roles required"
    )
    Store(store.connection, store.identity, [*store.old_logins, *names]).check()
    enabled = set()
    adjusted = []
    for item in replacements:
        observed = credentials.attributes(store, item.new)
        require(observed is not None, "serving principal missing")
        if observed["rolcanlogin"]:
            require(item.new in names, "unselected principal is enabled")
            enabled.add(item.new)
        adjusted.append(
            replace(item, attributes=dict(item.attributes, rolcanlogin=bool(item.new in enabled)))
        )
    # This checks the same OIDs, fixed privileges, exact retained verifier and
    # inert retired-name tombstones; only selected LOGIN bits may differ.
    require(credentials.status(store, adjusted) == "replaced-disabled", "serving roles differ")
    return enabled


def sql_enable(store: Store, replacements: list, names: set[str]) -> None:
    require(not sql_observed(store, replacements, names), "serving identities already enabled")
    with store.connection.transaction():
        for name in sorted(names):
            require(
                store.one(
                    "SELECT rolvaliduntil IS NULL OR rolvaliduntil>clock_timestamp() "
                    "FROM pg_authid WHERE rolname=%s",
                    (name,),
                ),
                "serving credential expired",
            )
            store.connection.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(name)))
        require(sql_observed(store, replacements, names) == names, "serving enablement differs")


def sql_disable(store: Store, replacements: list, names: set[str]) -> dict:
    sql_observed(store, replacements, names)
    # Commit exclusion before terminating connections, including after a lost
    # enable reply. Do not reset a finite expiration or erase application data.
    with store.connection.transaction():
        for name in sorted(names):
            store.connection.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(name)))
    store.connection.execute("SELECT pg_stat_clear_snapshot()")
    for (pid,) in store.rows(
        "SELECT pid FROM pg_stat_activity WHERE backend_type='client backend' "
        "AND usename=ANY(%s) AND pid<>pg_backend_pid()",
        (sorted(names),),
    ):
        require(
            store.one("SELECT pg_terminate_backend(%s,5000)", (pid,)), "serving backend remains"
        )
    store.connection.execute("SELECT pg_stat_clear_snapshot()")
    require(
        not store.one(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE backend_type='client backend' "
            "AND usename=ANY(%s))",
            (sorted(names),),
        ),
        "serving backend exit unconfirmed",
    )
    require(not sql_observed(store, replacements, names), "serving exclusion differs")
    return {"principals": sorted(names), "disabled": True, "remainingBackends": 0}


def token_observed(store: RedisStore, old_run_id: str, value: token.Credential) -> bool:
    require(store.identity["run_id"] != old_run_id, "retired token incarnation reused")
    inspected = RedisStore(
        store.connection, store.identity, store.administrator, ["default", value.name]
    )
    inspected.check()
    default = pairs(store.call("ACL", "GETUSER", "default"))
    require(
        set(default["flags"]) == {"off", "sanitize-payload"}
        and not default["passwords"]
        and not default["selectors"]
        and default["commands"] == "-@all"
        and default["keys"] == ""
        and default["channels"] == "",
        "default token identity is not excluded",
    )
    active = "on" in pairs(store.call("ACL", "GETUSER", value.name))["flags"]
    token.profile(store, value, enabled=active)
    current = str(store.call("CLIENT", "ID"))
    require(
        all(row["id"] == current or row["user"] == value.name for row in store.clients()),
        "unlisted serving token client",
    )
    return active


def token_enable(store: RedisStore, old_run_id: str, value: token.Credential) -> None:
    # Empty-store verification belongs only to the first registered start, before
    # any worker can write. Recovery uses token_disable without this condition.
    require(token.check(store, old_run_id, value), "exact empty prepared token store required")
    require(store.call("ACL", "SETUSER", value.name, "on") == "OK", "token enablement unconfirmed")
    require(store.call("ACL", "SAVE") == "OK", "serving token persistence unconfirmed")
    require(token_observed(store, old_run_id, value), "serving token profile differs")


def token_disable(store: RedisStore, old_run_id: str, value: token.Credential) -> dict:
    token_observed(store, old_run_id, value)
    require(store.call("ACL", "SETUSER", value.name, "off") == "OK", "token exclusion unconfirmed")
    require(store.call("ACL", "SAVE") == "OK", "token exclusion persistence unconfirmed")
    for client in store.clients():
        if client["user"] == value.name:
            require(
                store.call("CLIENT", "KILL", "ID", client["id"]) == 1,
                "serving token client remains",
            )
    require(not token_observed(store, old_run_id, value), "serving token exclusion differs")
    require(
        not any(row["user"] == value.name for row in store.clients()),
        "serving token client exit unconfirmed",
    )
    return {
        "identity": store.identity,
        "principal": value.name,
        "disabled": True,
        "remainingClients": 0,
    }
