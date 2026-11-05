"""Actual SCRAM, password expiration and terminated native-validation backends."""

from __future__ import annotations

import copy
import json
import time
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest
from psycopg import sql


def scenario(primary, replacements, password, output):  # noqa: PLR0915 — bounded SQL lease lifecycle
    import organization_cutover_credentials as credentials  # noqa: PLC0415
    import organization_cutover_login as login  # noqa: PLC0415

    # Change only this disposable cluster's local authentication for the one new
    # principal. A trust connection cannot demonstrate password expiration.
    hba = Path(primary.one("SHOW hba_file"))
    original = hba.read_text()
    hba.write_text("local all fresh_worker scram-sha-256\n" + original)
    primary.one("SELECT pg_reload_conf()")
    lease = login.plan(primary, replacements, {"fresh_worker"})
    (output / "fixture-login-lease.json").write_text(json.dumps(lease))
    login.enable(primary, replacements, lease)
    deadline = time.monotonic() + 5
    while True:
        try:
            with psycopg.connect(
                primary.connection.info.dsn,
                user="fresh_worker",
                password="wrong",  # noqa: S106 — negative authentication fixture
            ):
                pass
        except psycopg.OperationalError:
            break
        assert time.monotonic() < deadline
        time.sleep(0.02)
    try:
        with psycopg.connect(
            primary.connection.info.dsn,
            user="fresh_worker",
            password=password.decode(),
            autocommit=True,
        ) as worker:
            assert worker.execute("SELECT session_user::text").fetchone()[0] == "fresh_worker"
            with pytest.raises(Exception, match="already enabled"):
                login.enable(primary, replacements, lease)
            changed = copy.deepcopy(lease)
            changed["expires"] = (
                primary.one("SELECT clock_timestamp()") + timedelta(seconds=30)
            ).isoformat()
            with pytest.raises(Exception, match="expiration differs"):
                login.disable(primary, replacements, changed)
            first = login.disable(primary, replacements, lease)
            with pytest.raises(psycopg.OperationalError):
                worker.execute("SELECT 1")
        assert login.disable(primary, replacements, lease) == first
        assert credentials.status(primary, replacements) == "replaced-disabled"
        primary.connection.execute("ALTER ROLE fresh_worker VALID UNTIL '2031-01-01T00:00:00Z'")
        with pytest.raises(Exception, match="attributes differ"):
            credentials.status(primary, replacements)
        finite = [
            replace(replacements[0], attributes=credentials.attributes(primary, "fresh_worker"))
        ]
        bounded = login.plan(primary, finite, {"fresh_worker"})
        login.enable(primary, finite, bounded)
        login.disable(primary, finite, bounded)
        assert credentials.status(primary, finite) == "replaced-disabled"
        primary.connection.execute("ALTER ROLE fresh_worker VALID UNTIL 'infinity'")
        assert credentials.status(primary, replacements) == "replaced-disabled"
        expired = copy.deepcopy(lease)
        expired["expires"] = (
            primary.one("SELECT clock_timestamp()") - timedelta(seconds=1)
        ).isoformat()
        with pytest.raises(Exception, match="lease expired"):
            login.enable(primary, replacements, expired)
        # Simulate a previously enabled lease that has elapsed, without treating
        # expiration as evidence that a pre-existing backend has stopped.
        primary.connection.execute(
            sql.SQL("ALTER ROLE fresh_worker LOGIN VALID UNTIL {}").format(
                sql.Literal(expired["expires"])
            )
        )
        with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
            psycopg.connect(
                primary.connection.info.dsn, user="fresh_worker", password=password.decode()
            )
        login.disable(primary, replacements, expired)
        with pytest.raises(psycopg.OperationalError, match="not permitted to log in"):
            psycopg.connect(
                primary.connection.info.dsn, user="fresh_worker", password=password.decode()
            )
        assert credentials.status(primary, replacements) == "replaced-disabled"
        (output / "login-result.json").write_text(
            json.dumps(
                {
                    "status": "passed",
                    "conditions": [
                        "actual new password succeeds and wrong SCRAM password refuses",
                        "repeated enable and changed expiry refuse",
                        "NOLOGIN precedes confirmed backend exit and exact cleanup replays",
                        "expired retained lease cannot be enabled or authenticate",
                        "new secret survives cleanup; unbounded lifetime uses infinity syntax",
                        "finite original expiration stays exact; changed lifetime is refused",
                    ],
                    "activation": False,
                    "newCompositeDischarges": 0,
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        hba.write_text(original)
        primary.one("SELECT pg_reload_conf()")
