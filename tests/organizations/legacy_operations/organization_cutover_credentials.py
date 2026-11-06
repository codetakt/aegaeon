"""Offline SQL role replacement primitive; never enables a login or an epoch.

The coordinator must retain the independent drained fence and custody of fresh
password files throughout planning, rotation and reconciliation. These helpers
require an already authenticated offline store administrator, not runtime rights.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from organization_recovery_store import require
from organization_restore_inspect import drained
from psycopg import sql

if TYPE_CHECKING:
    from organization_recovery_store import Store

MAX_ROLES = 64
MIN_PASSWORD_BYTES = 32
MAX_PASSWORD_BYTES = 1024


@dataclass(frozen=True, repr=False)
class Replacement:
    old: str
    new: str
    attributes: dict = field(repr=False)
    verifier: bytes = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", normalized_attributes(self.attributes))


def normalized_attributes(value: dict) -> dict:
    # PostgreSQL represents an unbounded password lifetime as NULL or infinity.
    # ALTER ROLE restores it through the supported VALID UNTIL 'infinity' syntax;
    # never write pg_authid directly. Every finite expiration stays exact.
    return dict(value, rolvaliduntil=value["rolvaliduntil"] or "infinity")


def attributes(store: Store, name: str) -> dict | None:
    rows = store.rows(
        "SELECT to_jsonb(r)-'rolname'-'rolpassword' FROM pg_authid r WHERE rolname=%s", (name,)
    )
    return normalized_attributes(rows[0][0]) if rows else None


def plan(store: Store, names: dict[str, str], passwords: dict[str, bytes]) -> list[Replacement]:
    drained(store)
    require(
        0 < len(names) <= MAX_ROLES
        and set(names) == set(store.old_logins)
        and set(passwords) == set(names)
        and len(set(names.values())) == len(names)
        and not set(names).intersection(names.values()),
        "complete distinct credential mapping required",
    )
    require(
        all(re.fullmatch(r"[a-z][a-z0-9_]{0,62}", n) for n in [*names, *names.values()]),
        "invalid credential identity",
    )
    result = []
    for old, new in sorted(names.items()):
        require(attributes(store, new) is None, "replacement identity already exists")
        password = passwords[old]
        require(
            type(password) is bytes
            and len(password) >= MIN_PASSWORD_BYTES
            and len(password) <= MAX_PASSWORD_BYTES
            and b"\0" not in password,
            "bounded fresh secret required",
        )
        original = attributes(store, old)
        require(original is not None, "excluded principal missing")
        verifier = store.connection.pgconn.encrypt_password(
            password, new.encode(), b"scram-sha-256"
        )
        require(verifier.startswith(b"SCRAM-SHA-256$"), "explicit SCRAM verifier required")
        result.append(Replacement(old, new, original, verifier))
    return result


def status(store: Store, replacements: list[Replacement]) -> str:
    """Exact lost-reply reconciliation; never recreates a password or changes SQL."""
    original = rotated = 0
    for item in replacements:
        old, new = attributes(store, item.old), attributes(store, item.new)
        if old == item.attributes and new is None:
            require(
                store.one(
                    "SELECT rolpassword IS NULL FROM pg_authid WHERE rolname=%s", (item.old,)
                ),
                "old credential unexpectedly present",
            )
            original += 1
            continue
        require(new == item.attributes, "replacement role identity or attributes differ")
        require(
            store.one("SELECT rolpassword FROM pg_authid WHERE rolname=%s", (item.new,))
            == item.verifier.decode(),
            "replacement verifier differs",
        )
        require(
            old is not None
            and old["oid"] != item.attributes["oid"]
            and not old["rolcanlogin"]
            and not old["rolsuper"]
            and not old["rolcreatedb"]
            and not old["rolcreaterole"]
            and not old["rolreplication"]
            and not old["rolbypassrls"]
            and not old["rolinherit"],
            "retired name is not an inert tombstone",
        )
        require(
            store.one(
                "SELECT rolpassword IS NULL AND NOT EXISTS(SELECT FROM pg_auth_members "
                "WHERE roleid=r.oid OR member=r.oid OR grantor=r.oid) AND NOT EXISTS(SELECT FROM "
                "pg_shdepend WHERE refclassid='pg_authid'::regclass AND refobjid=r.oid) "
                "FROM pg_authid r WHERE rolname=%s",
                (item.old,),
            ),
            "retired identity has a secret or authority",
        )
        rotated += 1
    require(
        replacements and (original == len(replacements) or rotated == len(replacements)),
        "partial credential replacement refused",
    )
    return "excluded" if original else "replaced-disabled"


def rotate(store: Store, replacements: list[Replacement]) -> None:
    drained(store)
    require(
        {item.old for item in replacements} == set(store.old_logins),
        "replacement inventory differs",
    )
    with store.connection.transaction():
        # One database/cluster is dedicated to this operation. Names remain checked
        # after the lock; concurrent plans cannot silently overwrite a winner.
        store.connection.execute("SELECT pg_advisory_xact_lock(741126334621)")
        require(status(store, replacements) == "excluded", "inspect completed replacement")
        for item in replacements:
            store.connection.execute(
                sql.SQL("ALTER ROLE {} RENAME TO {}").format(
                    sql.Identifier(item.old), sql.Identifier(item.new)
                )
            )
            store.connection.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS PASSWORD NULL"
                ).format(sql.Identifier(item.old))
            )
            store.connection.execute(
                sql.SQL("ALTER ROLE {} NOLOGIN PASSWORD {}").format(
                    sql.Identifier(item.new), sql.Literal(item.verifier.decode())
                )
            )
        require(status(store, replacements) == "replaced-disabled", "replacement not confirmed")
