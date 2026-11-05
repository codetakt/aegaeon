"""Short native-validation login leases; never clear authority or pending work.

The coordinator must retain the exact lease before enablement and keep the live
deployment fence. Retrying first disables the lease and terminates its actual
backends. Expiration limits authentication; it is never proof of backend exit.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import organization_cutover_credentials as credentials
from organization_recovery_store import Store, require
from psycopg import sql

SECONDS = 60


def plan(store: Store, replacements: list, names: set[str]) -> dict:
    require(
        credentials.status(store, replacements) == "replaced-disabled", "disabled roles required"
    )
    require(
        names and names <= {item.new for item in replacements}, "retained validation roles required"
    )
    now = store.one("SELECT clock_timestamp()")
    return {
        "version": 1,
        "identity": store.identity,
        "names": sorted(names),
        "expires": (now + timedelta(seconds=SECONDS)).isoformat(),
    }


def observed(store: Store, replacements: list, lease: dict) -> list[str]:
    require(
        set(lease) == {"version", "identity", "names", "expires"}
        and lease["version"] == 1
        and lease["identity"] == store.identity
        and type(lease["names"]) is list
        and lease["names"] == sorted(set(lease["names"]))
        and lease["names"]
        and set(lease["names"]) <= {item.new for item in replacements},
        "exact retained validation lease required",
    )
    expiry = datetime.fromisoformat(lease["expires"])
    require(expiry.tzinfo is not None, "absolute validation deadline required")
    Store(store.connection, store.identity, [*store.old_logins, *lease["names"]]).check()
    active = []
    for item in replacements:
        actual = credentials.attributes(store, item.new)
        require(actual is not None, "validation principal missing")
        expected = item.attributes
        if item.new in lease["names"] and actual["rolcanlogin"]:
            valid = datetime.fromisoformat(actual["rolvaliduntil"])
            require(valid == expiry, "validation expiration differs")
            expected = dict(expected, rolcanlogin=True, rolvaliduntil=actual["rolvaliduntil"])
            active.append(item.new)
        require(actual == expected, "validation role attributes changed")
        require(
            store.one("SELECT rolpassword FROM pg_authid WHERE rolname=%s", (item.new,))
            == item.verifier.decode(),
            "validation verifier changed",
        )
    return sorted(active)


def enable(store: Store, replacements: list, lease: dict) -> None:
    # The private caller retains this lease and the independent intent before
    # this transaction. A partially enabled/expired lease is cleanup-only.
    require(not observed(store, replacements, lease), "validation lease already enabled")
    require(
        credentials.status(store, replacements) == "replaced-disabled", "disabled roles required"
    )
    remaining = datetime.fromisoformat(lease["expires"]) - store.one("SELECT clock_timestamp()")
    require(
        timedelta(seconds=5) < remaining <= timedelta(seconds=SECONDS), "validation lease expired"
    )
    with store.connection.transaction():
        for name in lease["names"]:
            store.connection.execute(
                sql.SQL("ALTER ROLE {} LOGIN VALID UNTIL {}").format(
                    sql.Identifier(name), sql.Literal(lease["expires"])
                )
            )
        require(observed(store, replacements, lease) == lease["names"], "login lease unconfirmed")


def disable(store: Store, replacements: list, lease: dict) -> dict:
    observed(store, replacements, lease)
    # A committed NOLOGIN must precede termination, so no new worker can enter
    # between the backend census and completion. Preserve the retained verifier.
    with store.connection.transaction():
        for item in replacements:
            if item.new in lease["names"]:
                store.connection.execute(
                    sql.SQL("ALTER ROLE {} NOLOGIN VALID UNTIL {}").format(
                        sql.Identifier(item.new),
                        sql.Literal(item.attributes["rolvaliduntil"] or "infinity"),
                    )
                )
    store.connection.execute("SELECT pg_stat_clear_snapshot()")
    backends = store.rows(
        "SELECT pid FROM pg_stat_activity WHERE backend_type='client backend' "
        "AND usename=ANY(%s) AND pid<>pg_backend_pid()",
        (lease["names"],),
    )
    for (pid,) in backends:
        require(
            store.one("SELECT pg_terminate_backend(%s,5000)", (pid,)), "validation backend remains"
        )
    store.connection.execute("SELECT pg_stat_clear_snapshot()")
    require(
        not store.one(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE backend_type='client backend' "
            "AND usename=ANY(%s))",
            (lease["names"],),
        ),
        "validation backend exit unconfirmed",
    )
    require(
        credentials.status(store, replacements) == "replaced-disabled",
        "disabled restoration differs",
    )
    return {"principals": lease["names"], "disabled": True, "remainingBackends": 0}
