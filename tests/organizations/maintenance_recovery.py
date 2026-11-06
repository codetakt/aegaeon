"""Actual SQL and service-managed maintenance recovery on owned local suppliers.

The service-manager case runs outside the Nix sandbox using only a unique system
unit. It does not qualify root credential delivery or production custody.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest


def run(*args):
    return subprocess.run(  # noqa: S603 — fixed fixture tools and owned paths
        args, check=True, capture_output=True, text=True, timeout=30
    ).stdout


def refused(function, message):
    with pytest.raises(Exception, match=message):
        function()


def sql_recovery_cases(stores, expected, output, operator):  # noqa: PLR0915 — ordered SQL acceptance
    """Actual SQL boundaries; service termination is not claimed in this mode."""
    from organization_recovery_store import clear, fence  # noqa: PLC0415

    control, primary = stores
    passed = []
    primary.connection.execute("CREATE DATABASE unlisted")
    refused(primary.check, "shared SQL cluster")
    primary.connection.execute("DROP DATABASE unlisted")
    primary.connection.execute("SET synchronous_commit=off")
    refused(primary.check, "durable offline administrator")
    primary.connection.execute("SET synchronous_commit=on")
    primary.connection.execute("BEGIN; INSERT INTO observed VALUES(2); PREPARE TRANSACTION 'owned'")
    refused(primary.check, "prepared SQL transaction")
    primary.connection.execute("ROLLBACK PREPARED 'owned'")
    passed.append("shared store, nondurable mode and detached prepared transaction refused")
    child, child_operation, child_epoch, primary_id, token_id = map(
        str, [uuid4() for _ in range(5)]
    )
    deployment = expected["deployment_id"]
    control.one(
        "SELECT organization_witness.initialize(%s,%s,%s)", (child, deployment, child_operation)
    )
    control.one(
        "SELECT organization_witness.prepare(%s,%s,%s,1,%s,%s,%s,%s,%s,%s)",
        (child, deployment, child_operation, child_epoch, primary_id, token_id, *["a" * 64] * 3),
    )
    with control.connection.transaction():
        refused(lambda: clear(control, expected, "b" * 64), "non-fenced child")
    control.one("SELECT organization_witness.fence(%s,%s,%s,2)", (child, deployment, str(uuid4())))
    passed.append("non-fenced child prevents maintenance reconciliation")

    # Load an explicit copy with the exclusion guard removed. The identical
    # refusal assertion must fail; do not present this as an old-code defect.
    source = operator / "share/aegaeon/scripts/operations/organization_recovery_store.py"
    original = source.read_text()
    guard = "self.check(excluded=True)"
    assert original.count(guard) == 3
    mutation = output / "credential-guard-mutant.py"
    mutation.write_text(original.replace(guard, "self.check(excluded=False)"))
    spec = importlib.util.spec_from_file_location("recovery_guard_mutant", mutation)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    mutant = module.Store(primary.connection, primary.identity, primary.old_logins)
    with pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"):
        refused(mutant.drain, "old credentials remain usable")
    passed.append("identical credential-refusal assertion detects guard-removal mutant")
    for store in stores:
        store.exclude()
        store.drain()
    with psycopg.connect(primary.connection.info.dsn, autocommit=True):
        refused(primary.drain, "unexpected client backend")
    assert control.one(
        "SELECT pending FROM organization_witness.maintenance_slots WHERE deployment_id=%s",
        (deployment,),
    )
    passed.append("concurrent recovery administrator prevents drain; pending retained")
    with control.connection.transaction():
        first = clear(control, expected, "b" * 64)
    with control.connection.transaction():
        assert clear(control, expected, "b" * 64) == first
        refused(lambda: clear(control, expected, "c" * 64), "completion differs")
        fence(control, deployment)
    assert not first["pending"]
    passed.append("conditional SQL completion exact replay; conflicting receipt refused")
    return passed


def main():  # noqa: C901, PLR0912, PLR0915 — one bounded actual-store lifecycle
    # The peer-refusal case permits directory traversal by another OS identity.
    # Keep every later secret private at creation, before its explicit chmod.
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operator", type=Path, required=True)
    parser.add_argument("--sql-only", action="store_true")
    parser.add_argument("--runtime-sql", action="store_true")
    parser.add_argument("--root-cli", action="store_true")
    parser.add_argument("--peer-cli", action="store_true")
    parser.add_argument("--runtime-cli", action="store_true")
    parser.add_argument("--restore-cli", action="store_true")
    parser.add_argument("--cutover-cli", action="store_true")
    parser.add_argument("--negative-runtime-drain", action="store_true")
    args = parser.parse_args()
    args.sql_only = args.sql_only or args.runtime_sql
    args.restore_cli = args.restore_cli or args.cutover_cli
    args.runtime_cli = args.runtime_cli or args.restore_cli
    args.peer_cli = args.peer_cli or args.runtime_cli
    sys.path.insert(0, str(args.operator / "share/aegaeon/scripts/operations"))
    from organization_recovery import inspect_recovery, recover, settings, stopped  # noqa: PLC0415
    from organization_recovery_store import Store, clear, fence  # noqa: PLC0415

    args.output.mkdir(mode=0o700)
    temporary = Path(tempfile.mkdtemp(prefix="aegaeon-maintenance-recovery-"))
    unit = "aegaeon-organization-maintenance-test-" + uuid4().hex + ".service"
    unit_dir = temporary / "systemd" if args.sql_only else Path("/run/systemd/system")
    unit_dir.mkdir(exist_ok=True, parents=True)
    unit_file = unit_dir / unit
    connections = []
    running = []
    passed = []
    try:
        stores = []
        config_stores = []
        for kind in ["control", "primary"]:
            data = temporary / kind
            socket = temporary / (kind + "-socket")
            socket.mkdir()
            run(
                "initdb",
                "-D",
                str(data),
                "-U",
                "postgres",
                "--no-locale",
                "--encoding=UTF8",
                "--auth-local=trust",
                "--auth-host=reject",
            )
            run(
                "pg_ctl",
                "-D",
                str(data),
                "-l",
                str(args.output / (kind + ".log")),
                "-w",
                "-t",
                "10",
                "-o",
                f"-k {socket} -c listen_addresses= -c max_prepared_transactions=4",
                "start",
            )
            running.append(data)
            connection = psycopg.connect(
                host=str(socket), dbname="postgres", user="postgres", autocommit=True
            )
            connections.append(connection)
            connection.execute("SET statement_timeout='10s'; SET lock_timeout='5s'")
            if kind == "control":
                for version in range(1, 17):
                    connection.execute(
                        (args.root / f"db/organization-witness/schema-v{version}.sql").read_text()
                    )
                connection.execute(
                    "CREATE ROLE old_worker LOGIN IN ROLE aegaeon_organization_witness_maintenance"
                )
            else:
                connection.execute("CREATE ROLE old_worker LOGIN")
                connection.execute(
                    "CREATE TABLE observed (value integer); GRANT INSERT ON observed TO old_worker"
                )
            identity = connection.execute(
                "SELECT jsonb_build_object('cluster',system_identifier::text,"
                "'database',current_database(),"
                "'database_oid',(SELECT oid::bigint FROM pg_database "
                "WHERE datname=current_database())) FROM pg_control_system()"
            ).fetchone()[0]
            stores.append(Store(connection, identity, ["old_worker"]))
            config_stores.append(
                {
                    "kind": kind,
                    "identity": identity,
                    "old_logins": ["old_worker"],
                    "connection": {
                        "host": "localhost",
                        "port": 5432,
                        "dbname": "postgres",
                        "user": "postgres",
                        "password_file": "/etc/aegaeon/fixture-password",
                        "ca_file": "/etc/aegaeon/fixture-ca",
                    },
                }
            )
        control, primary = stores
        deployment, operation, work = map(str, [uuid4(), uuid4(), uuid4()])
        control.one(
            "SELECT organization_witness.deployment_initialize(%s,%s)", (deployment, operation)
        )
        with psycopg.connect(
            host=str(temporary / "control-socket"),
            dbname="postgres",
            user="old_worker",
            autocommit=True,
        ) as worker:
            original = worker.execute(
                "SELECT organization_witness.maintenance_acquire(%s,%s,1,%s,'history-restore',%s)",
                (deployment, operation, work, "a" * 64),
            ).fetchone()[0]
        expected = {
            "deployment_id": deployment,
            "generation": 1,
            "work_id": work,
            "plan_sha256": "a" * 64,
        }
        config = settings(
            json.dumps(
                {"version": 1, "maintenance": expected, "stores": config_stores, "services": [unit]}
            )
        )
        refused(primary.drain, "old credentials remain usable")
        passed.append("usable old credentials refuse drain")
        wrong = Store(primary.connection, primary.identity | {"cluster": "1"}, ["old_worker"])
        refused(wrong.check, "identity differs")
        primary.connection.execute("CREATE ROLE unlisted LOGIN")
        refused(primary.check, "unlisted login")
        primary.connection.execute("DROP ROLE unlisted")
        primary.connection.execute("ALTER ROLE old_worker CREATEROLE")
        refused(primary.check, "escape credential exclusion")
        primary.connection.execute("ALTER ROLE old_worker NOCREATEROLE")
        passed.append("wrong supplier, unlisted and privileged credentials refused")

        if args.root_cli or args.peer_cli:
            from recovery_entry import root_entry  # noqa: PLC0415

            result = root_entry(temporary, stores, config, args)
            (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            return

        if args.sql_only:
            if args.runtime_sql:
                from runtime_recovery import scenario  # noqa: PLC0415

                scenario(stores, expected, args.output, args.operator)
                return
            passed.extend(sql_recovery_cases(stores, expected, args.output, args.operator))
            from cutover_credentials import scenario as credential_replacement  # noqa: PLC0415
            from cutover_journal import scenario as cutover_journal  # noqa: PLC0415

            cutover_journal(control, expected["deployment_id"], args.output, args.operator)
            credential_replacement(primary, args.output)
            (args.output / "result.json").write_text(
                json.dumps(
                    {
                        "passed": passed,
                        "actual_service_termination": False,
                        "operator": str(args.operator),
                        "new_atomic_discharge": 0,
                    },
                    indent=2,
                )
                + "\n"
            )
            return

        worker_script = temporary / "worker.py"
        worker_script.write_text(
            "import os, time, psycopg\n"
            "if os.fork() == 0:\n    time.sleep(120)\nelse:\n    c=psycopg.connect(host="
            + repr(str(temporary / "primary-socket"))
            + ",dbname='postgres',user='old_worker')\n"
            "    c.execute('INSERT INTO observed VALUES(1)')\n"
            "    c.execute('SELECT pg_sleep(110)')\n"
        )
        unit_source = temporary / "worker.service"
        unit_source.write_text(
            "[Unit]\nDescription=Aegaeon owned recovery fixture\n[Service]\nType=simple\nUser="
            + os.environ["USER"]
            + "\nKillMode=control-group\nDelegate=no\nSendSIGKILL=yes\nTimeoutStopSec=3\nExecStart="
            + sys.executable
            + " "
            + str(worker_script)
            + "\n"
            + "NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n"
        )
        run("sudo", "-n", "install", "-m", "644", str(unit_source), str(unit_file))
        run("sudo", "-n", "systemctl", "daemon-reload")
        run("sudo", "-n", "systemctl", "start", unit)
        deadline = time.monotonic() + 10
        while not primary.one(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='old_worker' "
            "AND query='SELECT pg_sleep(110)')"
        ):
            assert time.monotonic() < deadline, "worker never entered actual SQL"
            primary.connection.execute("SELECT pg_stat_clear_snapshot()")
            time.sleep(0.05)
        refused(lambda: stopped(unit, ("sudo", "-n", "systemctl")), "termination unconfirmed")
        passed.append("live worker and child are not accepted as stopped")
        # Actual filesystem refusal before COMMIT must leave durable pending and
        # permanently excluded credentials. Never overwrite the prior artifact.
        failed = args.output / "before-commit"
        failed.mkdir(mode=0o700)
        (failed / "reconciliation.json").write_bytes(b"retained predecessor")
        failed_fd = os.open(failed, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(FileExistsError):
                recover(config, stores, failed_fd, command=("sudo", "-n", "systemctl"))
        finally:
            os.close(failed_fd)
        assert control.one(
            "SELECT pending FROM organization_witness.maintenance_slots WHERE deployment_id=%s",
            (deployment,),
        )
        for store in stores:
            store.check(excluded=True)
        assert (failed / "reconciliation.json").read_bytes() == b"retained predecessor"
        passed.append("pre-COMMIT receipt failure retains pending and committed exclusions")
        # Lose the local post-COMMIT receipt without losing the synchronized
        # pre-COMMIT receipt. Read-only inspection must determine actual outcome.
        (args.output / "released.json").write_bytes(b"retained predecessor")
        output = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(FileExistsError):
                recover(config, stores, output, command=("sudo", "-n", "systemctl"))
        finally:
            os.close(output)
        receipt = (args.output / "reconciliation.json").read_bytes()
        assert inspect_recovery(config, control, receipt) == "completed"
        refused(lambda: inspect_recovery(config, control, receipt + b" "), "digest differs")
        result = control.one(
            "SELECT to_jsonb(s) FROM organization_witness.maintenance_slots s "
            "WHERE deployment_id=%s",
            (deployment,),
        )
        passed.append("lost completion receipt resolves read-only; altered bytes refused")
        assert not result["pending"]
        assert result["generation"] == 1
        assert primary.one("SELECT count(*) FROM observed") == 0
        stopped(unit, ("sudo", "-n", "systemctl"))
        passed.append("actual service/cgroup and SQL work stopped; uncommitted write rolled back")
        for kind, store in zip(["control", "primary"], stores, strict=True):
            store.check(excluded=True)
            refused(
                lambda kind=kind: psycopg.connect(
                    host=str(temporary / (kind + "-socket")),
                    dbname="postgres",
                    user="old_worker",
                    connect_timeout=2,
                ),
                "not permitted to log in",
            )
        passed.append("both old SQL credentials cannot reconnect")
        with control.connection.transaction():
            assert clear(control, expected, result["completion_sha256"]) == result
            fence(control, deployment)
        passed.append("exact SQL recovery replay preserves generation and fences")
        with control.connection.transaction():
            refused(
                lambda: clear(
                    control, expected | {"work_id": str(uuid4())}, result["completion_sha256"]
                ),
                "generation or plan differs",
            )
        assert (
            control.one(
                "SELECT to_jsonb(s) FROM organization_witness.maintenance_slots s "
                "WHERE deployment_id=%s",
                (deployment,),
            )
            == result
        )
        passed.append("foreign operation cannot reconcile the completed generation")
        assert original["principal"] == result["principal"]
        (args.output / "result.json").write_text(
            json.dumps(
                {
                    "passed": passed,
                    "operator": str(args.operator),
                    "actual_systemd_system_service": True,
                    "actual_independent_postgresql": True,
                    "production_root_custody_qualified": False,
                    "new_atomic_discharge": 0,
                    "activation": False,
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        try:
            if unit_file.exists():
                run("sudo", "-n", "systemctl", "stop", unit)
                run("sudo", "-n", "rm", "--", str(unit_file))
                run("sudo", "-n", "systemctl", "daemon-reload")
        finally:
            for connection in connections:
                connection.close()
            try:
                for data in reversed(running):
                    run("pg_ctl", "-D", str(data), "-w", "-t", "10", "-m", "immediate", "stop")
            finally:
                # Retain failed-stop data for diagnosis; never remove a live DB.
                if all(not (data / "postmaster.pid").exists() for data in running):
                    shutil.rmtree(temporary)


if __name__ == "__main__":

    def interrupted(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    main()
