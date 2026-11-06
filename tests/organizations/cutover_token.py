"""Actual TLS Redis preparation, persistence failure and strict empty-state checks."""

from __future__ import annotations

import json
import secrets

import pytest


def scenario(initial, connection, restart, temporary, output):  # noqa: PLR0915 — finite token lifecycle
    from organization_cutover_token import (  # noqa: PLC0415
        check,
        credential,
        prepare,
        validation_disable,
        validation_enable,
    )
    from organization_recovery_redis import pairs  # noqa: PLC0415

    password = secrets.token_urlsafe(32)
    value = credential(
        "fresh_worker", password.encode(), {"get", "set", "ping", "select", "info", "client|info"}
    )
    old_run_id = initial.identity["run_id"]
    with pytest.raises(Exception, match="new incarnation"):
        prepare(initial, old_run_id, value)
    store = restart()
    assert store.identity["run_id"] != old_run_id
    with pytest.raises(Exception, match="restricted Redis command"):
        credential("fresh_worker", password.encode(), {"acl|setuser"})
    store.call("SELECT", "15")
    store.call("SET", "old-root", "retained")
    store.call("SELECT", "0")
    with pytest.raises(Exception, match="retained data"):
        prepare(store, old_run_id, value)
    store.call("SELECT", "15")
    store.call("DEL", "old-root")
    store.call("SELECT", "0")
    other = connection()
    try:
        with pytest.raises(Exception, match="another live client"):
            prepare(store, old_run_id, value)
    finally:
        other.close()
    store.call("ACL", "SETUSER", "unknown", "off")
    with pytest.raises(Exception, match="login inventory"):
        prepare(store, old_run_id, value)
    store.call("ACL", "DELUSER", "unknown")
    temporary.chmod(0o500)
    try:
        with pytest.raises(Exception, match="Redis command refused"):
            prepare(store, old_run_id, value)
    finally:
        temporary.chmod(0o700)
    # The failed persistence operation closes the connection. Reconnect with the
    # same explicit plan; do not synthesize a successful old acknowledgement.
    store = type(store)(connection(), store.identity, "admin", ["default"])
    assert check(store, old_run_id, value)
    result = prepare(store, old_run_id, value)
    assert result["enabled"] is False
    assert result["activationAuthorized"] is False
    assert password not in json.dumps(result)
    assert prepare(store, old_run_id, value) == result
    altered = credential("fresh_worker", secrets.token_urlsafe(32).encode(), set(value.commands))
    with pytest.raises(Exception, match="profile differs"):
        prepare(store, old_run_id, altered)
    with pytest.raises(Exception, match="Redis command refused"):
        connection("fresh_worker", password)
    assert pairs(store.call("ACL", "GETUSER", "fresh_worker"))["passwords"] == [
        value.password_sha256
    ]
    validation_enable(store, old_run_id, value)
    worker = connection("fresh_worker", password)
    try:
        assert worker.call("PING") == "PONG"
        disabled = validation_disable(store, old_run_id, value)
        assert disabled["remainingClients"] == 0
        with pytest.raises(Exception, match=r"Redis|closed|eof"):
            worker.call("PING")
        assert validation_disable(store, old_run_id, value) == disabled
        with pytest.raises(Exception, match="Redis command refused"):
            connection("fresh_worker", password)
    finally:
        worker.close()
    old_identity = store.identity
    store = restart()
    assert store.identity != old_identity
    assert check(store, old_run_id, value)
    with pytest.raises(Exception, match="Redis command refused"):
        connection("fresh_worker", password)
    from cutover_serving_credentials import token_scenario  # noqa: PLC0415

    token_scenario(store, old_run_id, value, password, connection, output)
    (output / "result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "conditions": [
                    "actual new incarnation required",
                    "administrative command profile refused",
                    "retained data in another logical database refused",
                    "concurrent client refused",
                    "unlisted user refused",
                    "ACL SAVE failure remains disabled and reconnect uses same plan",
                    "exact replay succeeds; conflicting password refused",
                    "new credential cannot authenticate",
                    "actual restart preserves disabled profile and empty data",
                    "validation login connects; cleanup terminates actual client and replays",
                ],
                "scope": "Redis preparation component; coordinator/native command coverage remains",
                "activation": False,
                "newCompositeDischarges": 0,
            },
            indent=2,
        )
        + "\n"
    )
