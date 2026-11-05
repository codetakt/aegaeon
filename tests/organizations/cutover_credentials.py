"""Actual PostgreSQL role replacement; no fresh-login enablement or cutover."""

from __future__ import annotations

import json
import secrets

import psycopg
import pytest
from psycopg import sql


def scenario(primary, output):  # noqa: PLR0915 — finite actual SQL replacement/fault sequence
    import organization_cutover_credentials as credentials  # noqa: PLC0415

    password = secrets.token_urlsafe(32).encode()
    old_oid = primary.one("SELECT oid::bigint FROM pg_roles WHERE rolname='old_worker'")
    names = {"old_worker": "fresh_worker"}
    replacement = credentials.plan(primary, names, {"old_worker": password})
    assert credentials.status(primary, replacement) == "excluded"
    assert password.decode() not in repr(replacement)
    with pytest.raises(Exception, match="complete distinct"):
        credentials.plan(primary, {"old_worker": "old_worker"}, {"old_worker": password})
    with pytest.raises(Exception, match="bounded fresh"):
        credentials.plan(primary, names, {"old_worker": b"short"})

    class InjectedRollbackError(Exception):
        pass

    with pytest.raises(InjectedRollbackError), primary.connection.transaction():  # noqa: PT012
        credentials.rotate(primary, replacement)
        raise InjectedRollbackError
    assert credentials.status(primary, replacement) == "excluded"
    credentials.rotate(primary, replacement)
    assert credentials.status(primary, replacement) == "replaced-disabled"
    legacy_attributes = dict(replacement[0].attributes, rolvaliduntil=None)
    legacy = credentials.Replacement(
        replacement[0].old, replacement[0].new, legacy_attributes, replacement[0].verifier
    )
    assert credentials.status(primary, [legacy]) == "replaced-disabled"
    assert legacy_attributes["rolvaliduntil"] is None
    assert primary.one("SELECT oid::bigint FROM pg_roles WHERE rolname='fresh_worker'") == old_oid
    assert primary.one("SELECT has_table_privilege('fresh_worker','observed','INSERT')")
    assert not primary.one("SELECT has_table_privilege('old_worker','observed','INSERT')")
    with pytest.raises(Exception, match="inspect completed"):
        credentials.rotate(primary, replacement)
    for name in ("old_worker", "fresh_worker"):
        with pytest.raises(psycopg.OperationalError, match="not permitted to log in"):
            psycopg.connect(primary.connection.info.dsn, user=name, password=password.decode())
    with primary.connection.transaction():
        primary.connection.execute("GRANT INSERT ON observed TO old_worker")
        with pytest.raises(Exception, match="secret or authority"):
            credentials.status(primary, replacement)
        primary.connection.execute("REVOKE INSERT ON observed FROM old_worker")
    primary.connection.execute("ALTER ROLE fresh_worker PASSWORD NULL")
    with pytest.raises(Exception, match="verifier differs"):
        credentials.status(primary, replacement)
    primary.connection.execute(
        sql.SQL("ALTER ROLE fresh_worker PASSWORD {}").format(
            sql.Literal(replacement[0].verifier.decode())
        )
    )
    assert credentials.status(primary, replacement) == "replaced-disabled"
    from cutover_login import scenario as login_scenario  # noqa: PLC0415

    login_scenario(primary, replacement, password, output)
    from cutover_serving_credentials import sql_scenario  # noqa: PLC0415

    sql_scenario(primary, replacement, password, output)
    (output / "credentials-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "conditions": [
                    "exact role OID/grants preserved; old name is inert and unavailable",
                    "same-name and short-secret plans refused",
                    "outer transaction failure rolls back whole replacement",
                    "lost reply resolved read-only; repeated mutation refused",
                    "both old and new principals remain unable to log in",
                    "retired-name authority and changed verifier refused",
                ],
                "newCompositeDischarges": 0,
                "scope": "SQL primitive; no active credentials or cutover",
            },
            indent=2,
        )
        + "\n"
    )
