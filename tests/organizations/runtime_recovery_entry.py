"""Packaged root recovery across actual peer control, TLS SQL/Redis and services."""

from __future__ import annotations

import hashlib
import json
import secrets
import socket
import subprocess
import time
from contextlib import ExitStack
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb
from recovery_entry import port, run


def entry(temporary, config, args, private, *, password, certificate, key):  # noqa: C901,PLR0912,PLR0913,PLR0915 — ordered lifecycle
    from organization_recovery_redis import info  # noqa: PLC0415
    from organization_recovery_resp import Resp  # noqa: PLC0415
    from organization_recovery_store import Store, clear  # noqa: PLC0415

    server = None
    redis_links = []
    data = temporary / "runtime-redis"
    data.mkdir(mode=0o700)
    number = port()
    redis_password, worker_password = secrets.token_hex(32), secrets.token_hex(32)
    secret = temporary / "redis-admin-password"
    secret.write_text(redis_password)
    assert secret.stat().st_mode & 0o777 == 0o600, "secret readable before chmod"
    secret.chmod(0o600)
    run("sudo", "-n", "install", "-m", "600", str(secret), str(private / "redis-password"))
    acl = data / "users.acl"
    acl.write_text(
        f"user admin on >{redis_password} ~* &* +@all\n"
        "user default off resetpass -@all\n"
        f"user old_worker on >{worker_password} ~* +get +set +multi +exec\n"
    )
    acl.chmod(0o600)
    redis_config = data / "redis.conf"
    redis_config.write_text(
        f"bind 127.0.0.1\nport 0\ntls-port {number}\ntls-cert-file {certificate}\n"
        f"tls-key-file {key}\ntls-ca-cert-file {certificate}\ntls-auth-clients no\n"
        f'aclfile {acl}\ndir {data}\nappendonly yes\nappendfsync always\nsave ""\n'
    )
    executable = str(args.operator / "bin/aegaeon-organization-recovery")
    control_connection, primary_connection = [item["connection"] for item in config["stores"]]

    def connect_control():
        return psycopg.connect(
            host=control_connection["socket"],
            port=control_connection["port"],
            dbname="postgres",
            user="postgres",
            autocommit=True,
        )

    def install_config():
        path = temporary / "runtime-config.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        run("sudo", "-n", "install", "-m", "600", str(path), str(private / "runtime-config"))

    def cli(output, *flags, success=True):
        return run(
            "sudo",
            "-n",
            executable,
            "--config",
            str(private / "runtime-config"),
            "--output",
            str(private / output),
            *flags,
            success=success,
        )

    try:
        with (args.output / "runtime-redis.log").open("wb") as log:
            server = subprocess.Popen(["redis-server", str(redis_config)], stdout=log, stderr=log)  # noqa: S603,S607
        deadline = time.monotonic() + 10
        while True:
            assert server.poll() is None
            try:
                with socket.create_connection(("127.0.0.1", number), timeout=0.1):
                    break
            except OSError:
                assert time.monotonic() < deadline
                time.sleep(0.02)
        token_admin = Resp("localhost", number, certificate.read_text(), "admin", redis_password)
        redis_links.append(token_admin)
        token = {"run_id": info(token_admin.call("INFO", "server"))["run_id"], "database": 0}
        token_worker = Resp(
            "localhost", number, certificate.read_text(), "old_worker", worker_password
        )
        redis_links.append(token_worker)
        token_worker.call("SET", "committed", "preserved")
        token_worker.call("MULTI")
        token_worker.call("SET", "uncommitted", "not-visible")
        token_admin.close()
        with ExitStack() as setup:
            control = setup.enter_context(connect_control())
            primary = setup.enter_context(
                psycopg.connect(
                    host="localhost",
                    port=primary_connection["port"],
                    dbname="postgres",
                    user="postgres",
                    password=password,
                    sslmode="verify-full",
                    sslrootcert=str(certificate),
                    autocommit=True,
                )
            )
            store = Store(
                control, config["stores"][0]["identity"], config["stores"][0]["old_logins"]
            )
            with control.transaction():
                clear(store, config["maintenance"], "b" * 64)
            deployment = config["maintenance"]["deployment_id"]
            operation = control.execute(
                "SELECT operation_id::text FROM organization_witness.deployments "
                "WHERE deployment_id=%s",
                (deployment,),
            ).fetchone()[0]
            control.execute(
                "CREATE ROLE old_runtime LOGIN IN ROLE aegaeon_organization_witness_runtime"
            )
            config["stores"][0]["old_logins"].append("old_runtime")
            primary.execute(
                sql.SQL("ALTER ROLE old_worker PASSWORD {}").format(sql.Literal(worker_password))
            )
            pg = primary.execute(
                "SELECT jsonb_build_object('cluster_id',system_identifier,'database_oid',"
                "(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),"
                "'database_name',current_database(),'started_us',"
                "(extract(epoch from pg_postmaster_start_time())*1000000)::bigint,"
                "'timeline',(pg_control_checkpoint()).timeline_id,"
                "'wal_position',(pg_current_wal_lsn()-'0/0'::pg_lsn)::numeric) "
                "FROM pg_control_system()"
            ).fetchone()[0]

            def call(name, *values):
                statement = sql.SQL("SELECT organization_witness.{}({})").format(
                    sql.Identifier(name), sql.SQL(",").join(sql.Placeholder() for _ in values)
                )
                return control.execute(statement, values).fetchone()[0]

            epoch, primary_id, token_id, child, child_op, child_epoch = map(
                str, [uuid4() for _ in range(6)]
            )
            sha = "a" * 64
            call("initialize", child, deployment, child_op)
            call(
                "deployment_prepare",
                deployment,
                operation,
                1,
                epoch,
                primary_id,
                token_id,
                sha,
                sha,
                sha,
            )
            call("deployment_store_progress_pin", deployment, operation, 2, Jsonb(pg), Jsonb(token))
            with pytest.raises(Exception, match="deployment durable seal required"):
                call("deployment_activate", deployment, operation, 2, sha)
            # The administrator constructs the interrupted owner. This setup
            # seal is not evidence of physical store-continuity qualification.
            call("deployment_store_seal_pin", deployment, operation, 2, str(uuid4()))
            call("deployment_activate", deployment, operation, 2, sha)
            call(
                "prepare",
                child,
                deployment,
                child_op,
                1,
                child_epoch,
                primary_id,
                token_id,
                sha,
                sha,
                sha,
            )
            call("store_progress_pin", child, deployment, child_op, 2, Jsonb(pg), Jsonb(token))
            call("deployment_bind_child", deployment, epoch, child, child_epoch)
            call("activate", child, deployment, child_op, 2, sha)
            control.execute("SET SESSION AUTHORIZATION old_runtime")
            try:
                parent = call(
                    "deployment_acquire", deployment, epoch, primary_id, token_id, str(uuid4())
                )
                parent_args = tuple(
                    parent[k] for k in ("deployment_id", "slot", "generation", "epoch", "worker_id")
                )
                call("deployment_store_progress_begin", *parent_args)
                owned = call(
                    "deployment_acquire_child",
                    *parent_args,
                    child,
                    child_epoch,
                    primary_id,
                    token_id,
                    str(uuid4()),
                )
                child_args = tuple(owned[k] for k in ("slot", "generation", "epoch", "worker_id"))
                call("store_progress_begin", child, deployment, *child_args)
            finally:
                control.execute("RESET SESSION AUTHORIZATION")
            fence = str(uuid4())
            call("deployment_fence", deployment, fence, 3)
            call("fence", child, deployment, str(uuid4()), 3)
        config.pop("maintenance")
        config.update(
            version=2,
            runtime={
                "deployment_id": deployment,
                "recovery_id": str(uuid4()),
                "fence_operation_id": fence,
                "fence_revision": 4,
                "state_sha256": "0" * 64,
            },
            token={
                "identity": token,
                "old_logins": ["default", "old_worker"],
                "connection": {
                    "host": "localhost",
                    "port": number,
                    "user": "admin",
                    "password_file": str(private / "redis-password"),
                    "ca_file": str(private / "ca"),
                },
            },
        )
        install_config()
        cli("inventory", "--runtime-inventory")
        inventory = json.loads(run("sudo", "-n", "cat", str(private / "inventory/inventory.json")))
        cli("wrong-state", success=False)
        config["runtime"]["state_sha256"] = inventory["state_sha256"]
        install_config()
        # The SQL worker holds an actual uncommitted write while the separately
        # managed service has a live child; both must be stopped before release.
        worker_sql = psycopg.connect(
            host="localhost",
            port=primary_connection["port"],
            dbname="postgres",
            user="old_worker",
            password=worker_password,
            sslmode="verify-full",
            sslrootcert=str(certificate),
        )
        try:
            worker_sql.execute("INSERT INTO observed VALUES(7)")
            data.chmod(0o500)
            cli("failed-save", success=False)
            data.chmod(0o700)
            with connect_control() as connection:
                assert (
                    connection.execute(
                        "SELECT count(*) FROM organization_witness.deployment_slots WHERE pending"
                    ).fetchone()[0]
                    == 1
                )
                assert (
                    connection.execute(
                        "SELECT count(*) FROM organization_witness.slots WHERE pending"
                    ).fetchone()[0]
                    == 1
                )
                assert (
                    connection.execute(
                        "SELECT count(*) FROM organization_witness.runtime_recoveries"
                    ).fetchone()[0]
                    == 0
                )
            assert "activation not authorized" in cli("receipt")
            assert cli("receipt", "--inspect").strip() == "completed"
            cli("receipt", success=False)
            cli("repeated", success=False)
            with pytest.raises(psycopg.Error):
                worker_sql.execute("SELECT 1")
        finally:
            worker_sql.close()
        receipt = run("sudo", "-n", "cat", str(private / "receipt/reconciliation.json"))
        released = json.loads(run("sudo", "-n", "cat", str(private / "receipt/released.json")))
        assert hashlib.sha256(receipt.encode()).hexdigest() == released["completion_sha256"]
        assert released["prior_state"] == inventory["state"]
        with connect_control() as connection:
            assert (
                connection.execute(
                    "SELECT count(*) FROM organization_witness.deployment_slots WHERE pending"
                ).fetchone()[0]
                == 0
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM organization_witness.slots WHERE pending"
                ).fetchone()[0]
                == 0
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM organization_witness.deployment_store_observations "
                    "WHERE finished_wal IS NULL"
                ).fetchone()[0]
                == 1
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM organization_witness.store_observations "
                    "WHERE finished_wal IS NULL"
                ).fetchone()[0]
                == 1
            )
        observer = Resp("localhost", number, certificate.read_text(), "admin", redis_password)
        redis_links.append(observer)

        def no_old_clients():
            rows = observer.call("CLIENT", "LIST").splitlines()
            assert not any("user=old_worker" in row.split() for row in rows), (
                "old Redis client remains"
            )

        if args.negative_runtime_drain:
            with pytest.raises(AssertionError, match="old Redis client remains"):
                no_old_clients()
        else:
            no_old_clients()
        with psycopg.connect(
            host="localhost",
            port=primary_connection["port"],
            dbname="postgres",
            user="postgres",
            password=password,
            sslmode="verify-full",
            sslrootcert=str(certificate),
        ) as observer_sql:
            assert observer_sql.execute("SELECT count(*) FROM observed").fetchone()[0] == 0
        with pytest.raises(psycopg.Error, match="authentication failed"):
            psycopg.connect(
                host="localhost",
                port=primary_connection["port"],
                dbname="postgres",
                user="old_worker",
                password=worker_password,
                sslmode="verify-full",
                sslrootcert=str(certificate),
            )
        assert observer.call("GET", "committed") == "preserved"
        assert observer.call("GET", "uncommitted") is None
        with pytest.raises(Exception, match="Redis command refused"):
            Resp("localhost", number, certificate.read_text(), "old_worker", worker_password)
        if args.restore_cli:
            for connection in redis_links:
                connection.close()
            from restore_inspect_entry import entry as inspect_restore  # noqa: PLC0415

            inspect_restore(
                temporary,
                config,
                args,
                private,
                password=password,
                certificate=certificate,
                key=key,
            )
        (args.output / "runtime-reconciliation.json").write_text(receipt)
        return {
            "actual_packaged_root_runtime_recovery": True,
            "local_control_peer": True,
            "primary_and_token_tls": True,
            "actual_system_service_with_child": True,
            "failed_acl_save_retains_parent_child_pending": True,
            "exact_retry_after_partial_exclusion": True,
            "interrupted_progress_preserved": True,
            "read_only_completion": True,
            "old_token_credential_refused": True,
            "activation": False,
            "production_supplier_qualified": False,
            "operator": str(args.operator),
            "negative_missing_token_drain_detected": args.negative_runtime_drain,
        }
    finally:
        data.chmod(0o700)
        for connection in redis_links:
            connection.close()
        if server is not None and server.poll() is None:
            server.terminate()
            server.wait(timeout=10)
