"""Actual serving logins and closure retain accepted data after uncertain start."""

from __future__ import annotations

import json
from dataclasses import replace

import psycopg
import pytest


def sql_scenario(store, replacements, password, output):
    import organization_cutover_credentials as credentials  # noqa: PLC0415
    import organization_cutover_serving_credentials as serving  # noqa: PLC0415

    selected = {"fresh_worker"}
    store.connection.execute("ALTER ROLE fresh_worker VALID UNTIL '2031-01-01T00:00:00Z'")
    finite = [replace(replacements[0], attributes=credentials.attributes(store, "fresh_worker"))]
    before = store.one("SELECT count(*) FROM observed")
    with pytest.raises(Exception, match="selected serving roles"):
        serving.sql_enable(store, finite, {"other_worker"})
    serving.sql_enable(store, finite, selected)
    with psycopg.connect(
        store.connection.info.dsn,
        user="fresh_worker",
        password=password.decode(),
        autocommit=True,
    ) as worker:
        worker.execute("INSERT INTO observed VALUES(57)")
        with pytest.raises(Exception, match="already enabled"):
            serving.sql_enable(store, finite, selected)
        first = serving.sql_disable(store, finite, selected)
        with pytest.raises(psycopg.OperationalError):
            worker.execute("SELECT 1")
    assert serving.sql_disable(store, finite, selected) == first
    assert store.one("SELECT count(*) FROM observed") == before + 1
    assert credentials.attributes(store, "fresh_worker") == finite[0].attributes
    with pytest.raises(psycopg.OperationalError, match="not permitted to log in"):
        psycopg.connect(store.connection.info.dsn, user="fresh_worker", password=password.decode())
    store.connection.execute("ALTER ROLE fresh_worker VALID UNTIL '2000-01-01T00:00:00Z'")
    expired = [replace(finite[0], attributes=credentials.attributes(store, "fresh_worker"))]
    with pytest.raises(Exception, match="expired"):
        serving.sql_enable(store, expired, selected)
    assert not serving.sql_observed(store, expired, selected)
    store.connection.execute("ALTER ROLE fresh_worker VALID UNTIL 'infinity'")
    assert credentials.status(store, replacements) == "replaced-disabled"
    (output / "serving-sql-result.json").write_text(
        json.dumps(
            {
                "passed": True,
                "conditions": [
                    "only selected identities enabled",
                    "accepted write preserved after exclusion and backend exit",
                    "exclusion replay does not mutate data",
                    "finite expiration preserved and expired credential refused",
                ],
                "scope": "SQL credential primitive, not complete serving coordinator",
                "newCompositeDischarges": 0,
            },
            indent=2,
        )
        + "\n"
    )


def token_scenario(store, old_run_id, value, password, connection, output):  # noqa: PLR0913,PLR0917 — exact owned supplier and retained identity
    import organization_cutover_serving_credentials as serving  # noqa: PLC0415
    import organization_cutover_token as preparation  # noqa: PLC0415

    serving.token_enable(store, old_run_id, value)
    worker = connection(value.name, password)
    try:
        assert worker.call("SET", "serving-accepted", "retained") == "OK"
        store.call("SELECT", "15")
        store.call("SET", "serving-other-database", "retained")
        store.call("SELECT", "0")
        first = serving.token_disable(store, old_run_id, value)
        with pytest.raises(Exception, match=r"Redis|closed|eof"):
            worker.call("PING")
        # The old validation-only path cannot close a serving store because its
        # empty-state precondition no longer holds. Retain this actual contrast.
        with pytest.raises(Exception, match="retained data"):
            preparation.validation_disable(store, old_run_id, value)
        assert serving.token_disable(store, old_run_id, value) == first
        assert store.call("GET", "serving-accepted") == "retained"
        store.call("SELECT", "15")
        assert store.call("GET", "serving-other-database") == "retained"
        store.call("SELECT", "0")
        with pytest.raises(Exception, match="Redis command refused"):
            connection(value.name, password)
        with pytest.raises(Exception, match="retained data"):
            serving.token_enable(store, old_run_id, value)
    finally:
        worker.close()
    (output / "serving-token-result.json").write_text(
        json.dumps(
            {
                "passed": True,
                "conditions": [
                    "actual restricted serving connection",
                    "old empty-store closure rejected after accepted write",
                    "new closure and replay preserve both logical databases",
                    "closed credential and stale start refused",
                ],
                "scope": "Redis credential primitive, not complete serving coordinator",
                "newCompositeDischarges": 0,
            },
            indent=2,
        )
        + "\n"
    )
