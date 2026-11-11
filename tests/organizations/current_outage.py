"""Bounded DB-outage acceptance on the actual packaged server, not a benchmark."""

from __future__ import annotations

import json
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit
from uuid import uuid4

import psycopg
from current_database import connect
from current_http import ConnectionFailureError, pause, poll_all, probes, response
from current_process import check_cancellation, cleanup_scope, stop_owned, track_owned


class OutageFixture:
    def __init__(self, directory, package, admin_url, supplier, helpers):
        self.directory, self.admin_url = directory, admin_url
        self.cluster, self.pg = supplier
        self.root, self.env, self.run = helpers
        self.selected = json.loads((directory / "runtime.json").read_text())
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self.command = [
            str(package / "bin/aegaeon-organizations-server"),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ]
        self.environment = self.env | {
            "AEGAEON_RUNTIME_ISSUER_HOST": urlsplit(
                self.selected["environments"][0]["issuer"]
            ).hostname,
            "AEGAEON_ORGANIZATION_RUNTIME_CONFIG": str(directory / "runtime.json"),
        }
        self.running = True

    def pg_control(self, action, mode=None):
        command = [self.pg / "pg_ctl", "-D", self.cluster["data"], "-w", "-t", "20"]
        if mode:
            command += ["-m", mode]
        if action == "start":
            command += ["-l", self.directory / "outage-postgres.log"]
        result = self.run(
            [*command, action],
            timeout=25,
            supplier=self.cluster["data"] if action == "start" else None,
        )
        assert result.returncode == 0, "owned PostgreSQL control failed"
        self.running = action == "start"

    def ready(self, child):
        deadline = time.monotonic() + 45
        while True:
            check_cancellation()
            assert child.poll() is None, "packaged server exited before readiness"
            try:
                remaining = deadline - time.monotonic()
                assert remaining > 0, "readiness deadline"
                if response(self.base, "/ready", self.directory, timeout=min(38, remaining)) == 204:
                    return
            except (ConnectionFailureError, TimeoutError):
                pass
            assert time.monotonic() < deadline, "readiness deadline"
            time.sleep(0.1)

    def check_generation(self):
        check_cancellation()
        with connect(self.admin_url) as connection:
            current = connection.execute(
                "SELECT generation FROM aegaeon_lifecycle.current WHERE singleton"
            ).fetchone()[0]
            assert str(current) == self.selected["generation"], "outage changed generation"
            refused_code = None
            try:
                connection.execute(
                    "SELECT aegaeon_lifecycle.activate_v1(%s,%s,%s,%s)",
                    (self.selected["deployment_id"], current, uuid4(), uuid4()),
                )
            except psycopg.Error as error:
                refused_code = error.sqlstate
            else:
                message = "recovered worker did not fence activation"
                raise AssertionError(message)
            assert refused_code == "55006", "unexpected activation error"
        check_cancellation()

    def outage(self, child, mode, duration):
        check_cancellation()
        self.pg_control("stop", mode)
        until = time.monotonic() + duration
        # Let the deliberately brief readiness cache expire first.
        time.sleep(2)
        with probes(self.base, ("/ready", "/token"), self.directory) as pending:
            while time.monotonic() < until:
                check_cancellation()
                assert child.poll() is None, "temporary DB outage terminated server"
                assert (
                    response(self.base, "/health", self.directory, timeout=2, pending=pending)
                    == 200
                )
                pause(min(1, max(0, until - time.monotonic())), pending)
            poll_all(pending)
            assert all(probe.finished for probe in pending), "outage probe did not finish"
            refused = {probe.endpoint: probe.status for probe in pending}
        assert refused == {"/ready": 503, "/token": 503}, refused
        self.pg_control("start")
        self.ready(child)
        assert response(self.base, "/token", self.directory) in (400, 401), (
            "protocol did not resume"
        )
        self.check_generation()
        return {
            "stop_mode": mode,
            "outage_seconds": duration,
            "same_process_recovered": True,
            "refused": refused,
        }

    def stop(self, child):
        if not self.running:
            self.pg_control("start")
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=55)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
                raise

    def stale_generation(self):
        check_cancellation()
        # Deliberate authority refusal remains distinct from temporary outage.
        with connect(self.admin_url) as connection:
            connection.execute(
                "SELECT aegaeon_lifecycle.activate_v1(%s,%s,%s,%s)",
                (self.selected["deployment_id"], self.selected["generation"], uuid4(), uuid4()),
            )
        stale = self.run(self.command, environment=self.environment, timeout=15)
        assert stale.returncode != 0
        assert "selected database generation or runtime role refused" in stale.stderr
        assert "control-store" not in stale.stderr

    def exercise(self):
        with (self.directory / "outage-server.log").open("x") as log:
            child = None
            try:
                check_cancellation()
                child = subprocess.Popen(  # noqa: S603 — explicit packaged executable, private fixture
                    self.command,
                    cwd=self.root,
                    env=self.environment,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=log,
                    start_new_session=True,
                )
                track_owned(child)
                check_cancellation()
                self.ready(child)
                # Exceed the reported ~35s exit in both cases, and the ordinary
                # cleanup interval in the crash case. No user mutation replay.
                results = [
                    self.outage(child, mode, seconds)
                    for mode, seconds in (("fast", 45), ("immediate", 120))
                ]
            finally:
                primary_error = sys.exception()
                with cleanup_scope():
                    if child is not None:
                        try:
                            try:
                                self.stop(child)
                            finally:
                                stop_owned(child)
                        except BaseException as failure:
                            if primary_error is None:
                                raise
                            primary_error.add_note(
                                f"outage cleanup failed: {type(failure).__name__}"
                            )
            assert child.returncode == 0, "outage fixture server did not drain cleanly"
            check_cancellation()
        self.stale_generation()
        return {"outages": results, "stale_generation_explicitly_refused": True}


def exercise(directory, package, admin_url, supplier, helpers):
    return OutageFixture(directory, package, admin_url, supplier, helpers).exercise()
