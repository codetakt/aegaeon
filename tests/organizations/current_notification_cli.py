"""Packaged worker entrypoints on the current runtime fixture's real TLS database."""

from __future__ import annotations

import json
import os
import signal
import time
from functools import partial
from urllib.parse import urlsplit
from uuid import uuid4

from current_database import connect
from current_process import check_cancellation


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def events(path):
    # The worker emits bounded operational fields only. Retain its actual log in
    # the private fixture; do not copy credentials or proof data into a receipt.
    values = []
    for line in path.read_text().splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and isinstance(value.get("fields"), dict):
            values.append(value["fields"])
    return values


def signal_when_idle(child, log, signum):
    # The controller retains ownership of the process group on every failure.
    # A pidfd binds the requested signal to this still-owned process instance.
    deadline = time.monotonic() + 40
    descriptor = os.pidfd_open(child.pid)
    try:
        while True:
            check_cancellation()
            require(child.poll() is None, "worker exited before the committed idle cycle")
            if any(row.get("event") == "notification_cycle_completed" for row in events(log)):
                signal.pidfd_send_signal(descriptor, signum)
                return
            require(time.monotonic() < deadline, "worker readiness deadline")
            time.sleep(0.05)
    finally:
        os.close(descriptor)


def exercise(directory, package, admin_url, helpers):
    _, env, run = helpers
    config = directory / "notification-runtime.json"
    selected = json.loads(config.read_text())
    issuer = urlsplit(selected["environments"][0]["issuer"]).hostname
    runtime_role = urlsplit(selected["primary"]["url"]).username
    keys = directory / "notification-keys.json"
    environment = env | {
        "AEGAEON_ORGANIZATION_RUNTIME_CONFIG": str(config),
        "AEGAEON_RUNTIME_ISSUER_HOST": issuer,
    }
    binary = package / "bin/aegaeon-notification-worker"
    results = []
    for name, signum in [("once", None), ("term", signal.SIGTERM), ("int", signal.SIGINT)]:
        log = directory / ("notification-cli-" + name + ".log")
        arguments = [binary, "--key-file", keys]
        if signum is None:
            arguments.append("--once")
        result = run(
            arguments,
            environment=environment,
            private_log=log,
            timeout=60,
            before_wait=(
                None if signum is None else partial(signal_when_idle, log=log, signum=signum)
            ),
        )
        require(result.returncode == 0, "packaged notification worker failed")
        cycles = [row for row in events(log) if row.get("event") == "notification_cycle_completed"]
        require(cycles, "packaged worker did not report a committed cycle")
        require(
            all(row.get("claimed") is False and row.get("outcome") == "idle" for row in cycles),
            "already accepted work was attempted again",
        )
        with connect(admin_url) as connection:
            sessions = connection.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE usename=%s", (runtime_role,)
            ).fetchone()[0]
            generations = connection.execute(
                "SELECT count(*) FROM aegaeon_lifecycle.activations"
            ).fetchone()[0]
        require(sessions == 0 and generations == 1, "worker did not release its selected runtime")
        results.append({"case": name, "returncode": result.returncode, "idle_cycles": len(cycles)})
    results.extend(refusals(directory, package, admin_url, (environment, run)))
    return results


def refusals(directory, package, admin_url, helpers):
    environment, run = helpers
    keys = directory / "notification-keys.json"
    results = []
    result = run(
        [
            package / "bin/aegaeon-notification-worker",
            "--key-file",
            directory / "missing-keys.json",
            "--once",
        ],
        environment=environment,
        timeout=20,
    )
    require(result.returncode != 0 and not result.stdout, "worker accepted missing key custody")
    results.append({"case": "missing-key", "returncode": result.returncode})
    with connect(admin_url) as connection:
        domain, invitation = connection.execute(
            "SELECT domain_id,object_id FROM aegaeon.notification_messages"
        ).fetchone()
    result = run(
        [
            package / "bin/aegaeon-notification-reissue",
            "--key-file",
            keys,
            "--domain-id",
            domain,
            "--invitation-id",
            invitation,
            "--expected-delivery-revision",
            "0",
            "--operation-id",
            uuid4(),
        ],
        environment=environment,
        timeout=45,
    )
    require(result.returncode != 0 and not result.stdout, "reissue accepted a stale revision")
    require("notification reissue unavailable" in result.stderr, "unexpected CLI refusal")
    with connect(admin_url) as connection:
        count = connection.execute("SELECT count(*) FROM aegaeon.notification_messages").fetchone()[
            0
        ]
    require(count == 1, "refused reissue changed the outbox")
    results.append({"case": "reissue-stale-revision", "returncode": result.returncode})
    return results


def authority_refusal(directory, package, admin_url, helpers):
    """Drain a revoked, authentically issued message through the packaged CLI."""
    _, env, run = helpers
    config = directory / "notification-runtime.json"
    selected = json.loads(config.read_text())
    environment = env | {
        "AEGAEON_ORGANIZATION_RUNTIME_CONFIG": str(config),
        "AEGAEON_RUNTIME_ISSUER_HOST": urlsplit(selected["environments"][0]["issuer"]).hostname,
    }
    with connect(admin_url) as connection:
        pending = connection.execute(
            "SELECT count(*) FROM aegaeon.notification_messages "
            "WHERE state='pending' AND attempts=0"
        ).fetchone()[0]
    require(pending == 1, "missing unattempted refusal fixture")
    log = directory / "notification-cli-authority-refusal.log"
    result = run(
        [
            package / "bin/aegaeon-notification-worker",
            "--key-file",
            directory / "notification-keys.json",
            "--once",
        ],
        environment=environment,
        private_log=log,
        timeout=60,
    )
    require(result.returncode == 0, "definite refusal failed the one-batch command")
    records = events(log)
    cycles = [r for r in records if r.get("event") == "notification_cycle_completed"]
    require(
        any(
            r.get("outcome") == "not_admitted" and r.get("retry_status") == "authority_changed"
            for r in cycles
        ),
        "missing committed authority refusal",
    )
    require(
        not any(
            r.get("event") in {"notification_cycle_refused", "notification_transport_observed"}
            for r in records
        ),
        "refusal was sent or reported as unavailable",
    )
    with connect(admin_url) as connection:
        rows = connection.execute(
            "SELECT m.terminal_reason,m.encrypted_payload IS NULL,m.attempts,a.outcome,"
            "a.admitted_at IS NULL FROM aegaeon.notification_messages m "
            "JOIN aegaeon.notification_attempts a ON a.message_id=m.id ORDER BY m.terminal_reason"
        ).fetchall()
        active = connection.execute(
            "SELECT active_messages FROM aegaeon.notification_queue_capacity"
        ).fetchone()[0]
        sessions = connection.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE usename=%s",
            (urlsplit(selected["primary"]["url"]).username,),
        ).fetchone()[0]
    require(
        rows
        == [
            ("accepted", True, 1, "accepted", False),
            ("authority_changed", True, 1, "not_admitted", True),
            ("authority_changed", True, 1, "not_admitted", True),
        ],
        "unexpected attempt or terminal state after CLI refusal",
    )
    require(active == 0 and sessions == 0, "refusal leaked capacity or runtime sessions")
    return {
        "returncode": result.returncode,
        "not_admitted": 2,
        "accepted": 1,
        "active": active,
        "runtime_sessions": sessions,
    }
