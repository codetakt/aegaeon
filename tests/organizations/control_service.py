"""Exercise the generated PostgreSQL configuration; not a host custody proof."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


def run(*args, sql=None, env=None, accepted=True):
    result = subprocess.run(  # noqa: S603 - fixed argv to Nix tools, no shell
        args, input=sql, text=True, capture_output=True, timeout=30, env=env, check=False
    )
    if (result.returncode == 0) != accepted:
        raise AssertionError((args[0], result.returncode, result.stderr))
    return result.stdout.strip()


def main():  # noqa: PLR0915 — one ordered provision/start/refusal/restart/cleanup fixture.
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--pre-start", required=True)
    parser.add_argument("--schemas", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    root = args.root / "service"
    root.mkdir()
    data = args.root / "postgresql"
    # Keep the startup-guard fixture intact as a distinct stopped cluster.
    data.rename(root / "startup-cluster")
    credentials = args.root / "credentials"
    credentials.mkdir()
    socket = root / "socket"
    socket.mkdir()
    env = dict(os.environ, CREDENTIALS_DIRECTORY=str(credentials))
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(credentials / "server-key"),
        "-out",
        str(credentials / "server-certificate"),
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    )
    (credentials / "server-key").chmod(0o600)
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
    control = run("pg_controldata", str(data))
    identity = next(
        line.split(":", 1)[1].strip()
        for line in control.splitlines()
        if line.startswith("Database system identifier:")
    )
    (credentials / "cluster-identity").write_text(identity + "\n")
    running = False

    def start(options):
        nonlocal running
        run(
            "pg_ctl",
            "-D",
            str(data),
            "-l",
            str(root / "postgres.log"),
            "-w",
            "-t",
            "20",
            "-o",
            options,
            "start",
        )
        running = True

    def stop():
        nonlocal running
        run("pg_ctl", "-D", str(data), "-w", "-t", "20", "-m", "fast", "stop")
        running = False

    def admin(sql, database="aegaeon_organization_control"):
        return run(
            "psql",
            "-X",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            "-h",
            str(socket),
            "-U",
            "postgres",
            "-d",
            database,
            sql=sql,
        )

    def client(sql, role="runtime", *, accepted=True, **options):
        settings = {
            "PGHOST": "localhost",
            "PGHOSTADDR": "127.0.0.1",
            "PGPORT": "5432",
            "PGDATABASE": "aegaeon_organization_control",
            "PGUSER": "organization_" + role,
            "PGPASSWORD": "fixture-only-" + role,
            "PGSSLMODE": "verify-full",
            "PGSSLROOTCERT": str(credentials / "server-certificate"),
            "PGCONNECT_TIMEOUT": "3",
            **options,
        }
        return run(
            "psql",
            "-X",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            sql=sql,
            env=dict(env, **settings),
            accepted=accepted,
        )

    try:
        # Provision with the listener disabled before installing the real HBA.
        start(f"-c listen_addresses='' -c unix_socket_directories={socket}")
        admin("CREATE DATABASE aegaeon_organization_control;", "postgres")
        for version in range(1, 17):
            admin((args.schemas / f"schema-v{version}.sql").read_text())
        for role in ("runtime", "maintenance"):
            admin(
                f"CREATE ROLE organization_{role} LOGIN PASSWORD 'fixture-only-{role}';"
                f"GRANT aegaeon_organization_witness_{role} TO organization_{role};"
            )
        stop()
        run(args.pre_start, env=env)
        start(f"-c unix_socket_directories={socket}")
        assert client("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()") == "t"
        assert (
            client(
                "SELECT current_setting('fsync'),current_setting('full_page_writes'),"
                "current_setting('synchronous_commit')"
            )
            == "on|on|on"
        )
        assert client("SHOW statement_timeout") == "10s"
        assert client("SHOW lock_timeout") == "5s"
        assert client("SHOW max_connections") == "96"
        environment = "00000000-0000-4000-8000-000000000001"
        deployment = "00000000-0000-4000-8000-000000000002"
        operation = "00000000-0000-4000-8000-000000000003"
        initialize = (
            f"SELECT organization_witness.initialize('{environment}','{deployment}','{operation}')"
        )
        client(initialize, accepted=False)
        client(initialize, "maintenance", accepted=False)
        parent_initialize = (
            f"SELECT organization_witness.deployment_initialize('{deployment}','{operation}')"
        )
        client(parent_initialize, accepted=False)
        parent = json.loads(client(parent_initialize, "maintenance"))
        assert parent["phase"] == "fenced"
        original = json.loads(client(initialize, "maintenance"))
        assert original["phase"] == "fenced"
        assert original["revision"] == 1
        current = f"SELECT organization_witness.current_state('{environment}','{deployment}')"
        assert json.loads(client(current)) == original
        client(initialize, "maintenance", accepted=False)
        for role in ("runtime", "maintenance"):
            client("SELECT * FROM organization_witness.authorities", role, accepted=False)
            client("SET ROLE aegaeon_organization_witness_owner", role, accepted=False)
        client("SELECT 1", accepted=False, PGSSLMODE="disable")
        client("SELECT 1", accepted=False, PGPASSWORD="wrong-fixture-password")
        client("SELECT 1", accepted=False, PGHOST="wrong.example")
        client("SELECT 1", accepted=False, PGDATABASE="postgres")
        client("SELECT 1", accepted=False, PGUSER="postgres")
        client("SELECT 1", accepted=False, PGSSLROOTCERT=str(root / "missing-ca"))
        stop()
        client(current, accepted=False)
        run(args.pre_start, env=env)
        start(f"-c unix_socket_directories={socket}")
        assert json.loads(client(current)) == original
        # Closing the DB and reopening it does not reset control history.
        client(initialize, "maintenance", accepted=False)
        args.receipt.write_text(
            json.dumps(
                {
                    "status": "passed",
                    "schema_versions": list(range(1, 17)),
                    "normal": [
                        "TLS verify-full/SCRAM",
                        "durability and timeouts",
                        "maintenance initialization",
                        "runtime current state",
                        "restart preserves fenced authority",
                    ],
                    "refusals": [
                        "runtime initialization",
                        "reinitialization before and after restart",
                        "runtime and maintenance direct table/owner access",
                        "plaintext",
                        "wrong password",
                        "wrong hostname",
                        "wrong database",
                        "administrator login",
                        "missing CA",
                        "outage",
                    ],
                    "limits": [
                        "psql client, not Rust Control::checked",
                        "credential paths redirected inside sandbox",
                        "no systemd mount/credential delivery",
                        "no physical backup/restore custody qualification",
                        "no active history/epoch transition or full-capacity acceptance",
                    ],
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        if running:
            stop()
        # Do not export fixture keys or database contents from the derivation.
        shutil.rmtree(credentials)


if __name__ == "__main__":
    main()
