"""Bounded restart/whole-store rollback for the owned production TLS fixture."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field
from uuid import UUID

CASE = "AEGAEON_TEST_ORGANIZATION_STORE_RESTART_CASE"
DIRECTORY = "AEGAEON_TEST_ORGANIZATION_STORE_RESTART_DIRECTORY"
EXPECT = "AEGAEON_TEST_ORGANIZATION_STORE_RESTART_EXPECT"
PROBE = "organization_production_store_restart_probe"
MARKER = "store-restart-probe: attempted=1 refused=1"
CASES = frozenset(
    {
        "postgres",
        "redis",
        "postgres-rollback",
        "redis-rollback",
        "pending-postgres",
        "pending-redis",
    }
)


def private_json(path, value):
    """Publish only complete private records; no credentials enter public reports."""
    temporary = path.with_suffix(".partial")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


@dataclass(slots=True)
class StoreRestart:
    """Own only the processes/data already provisioned by production_runtime.py.

    The caller must copy ``driver.token`` back to its cleanup owner in a finally
    block, including when ``drive`` fails after replacing the Redis process.
    """

    case: str
    directory: object
    temporary: object
    binary: object
    environment: dict
    run: object
    sql: object
    setup: object
    clusters: dict
    postgres_bin: object
    redis_bin: object
    redis_config: object
    token: object
    setup_log: object
    database: str
    output: object
    report: dict = field(init=False, default_factory=dict)
    _child: object = field(init=False, default=None)
    _index: int = field(init=False, default=0)
    _nonce: str = field(init=False, default="")
    _sequence: int = field(init=False, default=0)
    _deadline: float = field(init=False, default=0)
    _phase_deadline: float = field(init=False, default=0)
    _copied: int = field(init=False, default=0)
    _restart_rows: int = field(init=False, default=0)

    def __post_init__(self):
        if self.case not in CASES or not self.directory.is_relative_to(self.temporary):
            message = "owned store restart selection differs"
            raise ValueError(message)
        self.directory.mkdir(mode=0o700)
        self.environment.update({CASE: self.case, DIRECTORY: str(self.directory)})
        self.report.update(case=self.case, fresh_process_attempts=0, completed=False)

    def _check(self):
        now = time.monotonic()
        if self._child.poll() is not None or now >= min(self._deadline, self._phase_deadline):
            message = "owned store restart controller exited or exceeded deadline"
            raise RuntimeError(message)

    def _timeout(self, maximum):
        self._check()
        return min(
            maximum, self._deadline - time.monotonic(), self._phase_deadline - time.monotonic()
        )

    def _progress(self):
        self._check()
        self._sequence += 1
        private_json(
            self.directory / f"heartbeat-{self._index}.json",
            {"version": 1, "nonce": self._nonce, "sequence": self._sequence},
        )

    def _request(self, phase):
        self._phase_deadline = min(self._deadline, time.monotonic() + 290)
        path = self.directory / f"request-{self._index}.json"
        while not path.exists():
            self._check()
            time.sleep(0.02)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024:
            message = "owned restart request is not a bounded regular record"
            raise RuntimeError(message)
        request = json.loads(path.read_text())
        expected = {"version": 1, "nonce": request.get("nonce"), "phase": phase, "case": self.case}
        if (
            request != expected
            or type(request.get("version")) is not int
            or UUID(request["nonce"]).int == 0
        ):
            message = "owned restart request differs from the expected phase"
            raise RuntimeError(message)
        self._nonce = request["nonce"]
        self._progress()

    def _reply(self, phase):
        self._progress()
        private_json(
            self.directory / f"reply-{self._index}.json",
            {"version": 1, "nonce": self._nonce, "phase": phase, "success": True},
        )

    def _command(self, argv):
        self._progress()
        self.setup(argv, timeout=self._timeout(25))
        self._progress()

    def _stop_postgres(self):
        self._command(
            [
                self.postgres_bin / "pg_ctl",
                "-D",
                self.clusters["primary"]["data"],
                "-w",
                "-t",
                "20",
                "-m",
                "fast",
                "stop",
            ]
        )

    def _start_postgres(self):
        self._command(
            [
                self.postgres_bin / "pg_ctl",
                "-D",
                self.clusters["primary"]["data"],
                "-l",
                self.output / "primary-postgres.log",
                "-w",
                "-t",
                "20",
                "start",
            ]
        )

    def _stop_redis(self):
        self._progress()
        if self.token.poll() is not None:
            message = "owned Redis exited before the requested stop"
            raise RuntimeError(message)
        self.token.send_signal(signal.SIGTERM)
        if self.token.wait(timeout=self._timeout(20)) != 0:
            message = "owned Redis did not stop cleanly"
            raise RuntimeError(message)
        self._progress()

    def _start_redis(self):
        self._progress()
        self.token = subprocess.Popen(  # noqa: S603 — fixed owned Redis executable/configuration
            [str(self.redis_bin / "redis-server"), str(self.redis_config)],
            env=self.environment,
            stdout=self.setup_log,
            stderr=self.setup_log,
            start_new_session=True,
        )
        port = int(re.search(r"(?m)^tls-port ([0-9]+)$", self.redis_config.read_text())[1])
        deadline = time.monotonic() + self._timeout(10)
        while True:
            self._progress()
            if self.token.poll() is not None or time.monotonic() >= deadline:
                message = "restarted owned Redis exited or exceeded startup deadline"
                raise RuntimeError(message)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.02)

    def _copy_file(self, source, target):
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with source.open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
            while chunk := incoming.read(1024 * 1024):
                self._progress()
                self._copied += len(chunk)
                if self._copied > 512 * 1024 * 1024:
                    message = "whole-store fixture copy exceeded its 512MiB bound"
                    raise RuntimeError(message)
                outgoing.write(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())

    def _copy_tree(self, source, target):
        self._copied = 0
        target.mkdir(mode=0o700)
        pending = [(source, target)]
        entries = 0
        while pending:
            origin, destination = pending.pop()
            for path in sorted(origin.iterdir()):
                self._progress()
                entries += 1
                if path.is_symlink() or entries > 20000:
                    message = "whole-store fixture copy has links or too many entries"
                    raise RuntimeError(message)
                output = destination / path.name
                if path.is_dir():
                    output.mkdir(mode=0o700)
                    pending.append((path, output))
                elif path.is_file():
                    self._copy_file(path, output)
                else:
                    message = "whole-store fixture copy contains a non-file entry"
                    raise RuntimeError(message)

    def _redis_files(self):
        return [self.temporary / "appendonlydir", self.temporary / "dump.rdb"]

    def _snapshot(self, store):
        snapshot = self.directory / "snapshot"
        if store == "postgres":
            self._stop_postgres()
            self._copy_tree(self.clusters["primary"]["data"], snapshot)
            self._start_postgres()
        else:
            self._stop_redis()
            snapshot.mkdir(mode=0o700)
            for source in self._redis_files():
                if source.is_dir():
                    self._copy_tree(source, snapshot / source.name)
                elif source.is_file():
                    self._copy_file(source, snapshot / source.name)
            self._start_redis()
        self.report["snapshot_scope"] = (
            "whole PostgreSQL cluster" if store == "postgres" else "all AOF/RDB data"
        )

    def _restore(self, store):
        snapshot = self.directory / "snapshot"
        if store == "postgres":
            self._stop_postgres()
            data = self.clusters["primary"]["data"]
            shutil.rmtree(data)
            self._copy_tree(snapshot, data)
            self._start_postgres()
            self._catch_up_wal()
        else:
            self._stop_redis()
            for path in self._redis_files():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
                source = snapshot / path.name
                if source.is_dir():
                    self._copy_tree(source, path)
                elif source.is_file():
                    self._copy_file(source, path)
            self._start_redis()

    def _cycle(self, store):
        if store == "postgres":
            self._stop_postgres()
            self._start_postgres()
        else:
            self._stop_redis()
            self._start_redis()

    def _query(self, kind, statement, database="postgres"):
        self._progress()
        value = self.sql(kind, statement, database, timeout=self._timeout(20))
        self._progress()
        return value

    def _catch_up_wal(self):
        target = int(
            self._query(
                "control",
                "SELECT greatest("
                "COALESCE((SELECT max(wal_position) FROM "
                "organization_witness.deployment_store_checkpoints),0),"
                "COALESCE((SELECT max(wal_position) FROM "
                "organization_witness.store_checkpoints),0))::text",
            )
        )
        deadline = time.monotonic() + 15
        emitted = 0
        while True:
            current = int(
                self._query(
                    "primary",
                    "SELECT pg_wal_lsn_diff(pg_current_wal_lsn(),'0/0')::text",
                    self.database,
                )
            )
            if current >= target:
                break
            if time.monotonic() >= deadline or emitted >= 32 * 1024 * 1024:
                message = "restored PostgreSQL WAL did not reach the retained floor within bounds"
                raise RuntimeError(message)
            self._query(
                "primary",
                "SELECT pg_logical_emit_message(true,"
                "'aegaeon-store-restart-fixture',repeat('x',65536))",
                self.database,
            )
            emitted += 65536
        self.report.update(
            wal_floor=target, restored_wal=current, emitted_wal_payload_bytes=emitted
        )

    def _inventory(self, label):
        names = json.loads(
            self._query(
                "control",
                "SELECT jsonb_agg(relname ORDER BY relname) FROM pg_catalog.pg_class "
                "WHERE relnamespace='organization_witness'::regnamespace AND relkind IN ('r','p')",
            )
        )
        inventory = {}
        for name in names:
            if not re.fullmatch(r"[a-z_]+", name):
                message = "control table name differs from the owned schema"
                raise RuntimeError(message)
            inventory[name] = json.loads(
                self._query(
                    "control",
                    "SELECT COALESCE(jsonb_agg(row ORDER BY row::text),'[]'::jsonb) "  # noqa: S608 — schema names checked above
                    f'FROM (SELECT to_jsonb(t) AS row FROM organization_witness."{name}" t) x',
                )
            )
        private_json(self.output / f"store-restart-{label}.json", inventory)
        digest = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
        self.report.setdefault("control_inventory_sha256", {})[label] = digest
        return inventory

    def _probes(self, count, reason):
        environment = self.environment | {EXPECT: "refuse"}
        for index in range(count):
            self._progress()
            result = self.run(
                [self.binary, PROBE, "--ignored", "--nocapture", "--test-threads=1"],
                environment=environment,
                timeout=self._timeout(20),
            )
            self._progress()
            prefix = self.output / f"store-restart-probe-{index + 1:02d}"
            prefix.with_suffix(".stdout").write_text(result.stdout)
            prefix.with_suffix(".stderr").write_text(result.stderr)
            diagnostic = result.stdout + result.stderr
            if (
                result.returncode
                or "1 passed" not in result.stdout
                or diagnostic.count(MARKER) != 1
            ):
                message = "fresh production startup refusal probe did not complete exactly once"
                raise RuntimeError(message)
            if diagnostic.count(reason) != 1:
                message = "fresh production startup refusal had a different reason"
                raise RuntimeError(message)
            self.report["fresh_process_attempts"] += 1
        self.report["refusal_reason"] = reason

    def _refusals(self, store, *, pending):
        if pending:
            before = self._inventory("before")
            self._cycle(store)
        else:
            self._restore(store)
            before = self._inventory("before")
        self._probes(
            1 if pending else 70,
            "store_restart_pending" if pending else "store_continuity_mismatch",
        )
        after = self._inventory("after")
        if before != after:
            message = "refused startup attempts changed durable control state"
            raise RuntimeError(message)
        self.report.update(control_unchanged=True, durable_control_tables=len(before))

    def drive(self, child):
        self._child = child
        self._deadline = time.monotonic() + 580
        phases = (
            ["pending", "complete"]
            if self.case.startswith("pending-")
            else (
                ["snapshot", "restore", "complete"]
                if self.case.endswith("-rollback")
                else ["restart", "complete"]
            )
        )
        store = "postgres" if "postgres" in self.case else "redis"
        for self._index, phase in enumerate(phases, 1):
            self._request(phase)
            self._phase(phase, store)
            self._reply(phase)
        self.report["completed"] = True

    def _phase(self, phase, store):
        if phase in {"restart", "snapshot"}:
            self._restart_rows = int(
                self._query(
                    "control", "SELECT count(*) FROM organization_witness.deployment_store_restarts"
                )
            )
            if phase == "restart":
                self._cycle(store)
            else:
                self._snapshot(store)
        elif phase in {"pending", "restore"}:
            self._refusals(store, pending=phase == "pending")
        elif not self.case.startswith("pending-"):
            rows = int(
                self._query(
                    "control", "SELECT count(*) FROM organization_witness.deployment_store_restarts"
                )
            )
            if rows != self._restart_rows + 1:
                message = "quiet store restart was not accepted exactly once"
                raise RuntimeError(message)
            self.report["restart_acceptances"] = rows - self._restart_rows
            if not self.case.endswith("-rollback"):
                self._runtime_outcomes()

    def _runtime_outcomes(self):
        outcome = json.loads((self.directory / "outcomes.json").read_text())
        expected = {
            "version": 1,
            "case": self.case,
            "same_runtime_work_after_restart": True,
            "rebuilt_runtime_work_after_restart": True,
            "application_postgres_read": True,
            "application_token_store_read": "try_get_bearer_meta_async",
        }
        if outcome != expected:
            message = "live and rebuilt runtime restart outcomes differ"
            raise RuntimeError(message)
        self.report.update(outcome)
