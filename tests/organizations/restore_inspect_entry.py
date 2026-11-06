"""Actual packaged restore inspector after runtime/credential exclusion."""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql
from recovery_entry import port, run


def entry(temporary, config, args, private, *, password, certificate, key):  # noqa: PLR0913,PLR0915
    import organization_recovery_runtime as runtime  # noqa: PLC0415
    from organization_recovery_store import Store  # noqa: PLC0415

    data, socket = temporary / "restore-target", temporary / "restore-socket"
    socket.mkdir()
    number = port()
    run(
        "initdb",
        "-D",
        str(data),
        "-U",
        "postgres",
        "--no-locale",
        "--encoding=UTF8",
        "--auth-local=trust",
        "--auth-host=scram-sha-256",
    )
    with (data / "postgresql.conf").open("a") as handle:
        handle.write(
            f"\nlisten_addresses='127.0.0.1'\nport={number}\nssl=on\n"
            f"ssl_cert_file='{certificate}'\nssl_key_file='{key}'\n"
            f"unix_socket_directories='{socket}'\n"
        )
    run("pg_ctl", "-D", str(data), "-l", str(args.output / "restore-target.log"), "-w", "start")
    conditions = []
    control_config, source_config = config["stores"]
    control_options = {
        "host": control_config["connection"]["socket"],
        "port": control_config["connection"]["port"],
        "dbname": "postgres",
        "user": "postgres",
    }
    source_options = {
        "host": "localhost",
        "port": source_config["connection"]["port"],
        "dbname": "postgres",
        "user": "postgres",
        "password": password,
        "sslmode": "verify-full",
        "sslrootcert": str(certificate),
    }
    target_options = {"host": str(socket), "port": number, "dbname": "postgres", "user": "postgres"}
    executable = str(args.operator / "bin/aegaeon-organization-restore-inspect")
    inspected = None

    def install_and_run(name, *, success=True):
        path = temporary / "restore-config.json"
        path.write_text(json.dumps(inspected))
        path.chmod(0o600)
        run("sudo", "-n", "install", "-m", "600", str(path), str(private / "restore-config"))
        return run(
            "sudo",
            "-n",
            executable,
            "--config",
            str(private / "restore-config"),
            "--output",
            str(private / name),
            success=success,
        )

    try:
        with psycopg.connect(**target_options, autocommit=True) as target:
            target.execute(sql.SQL("ALTER ROLE postgres PASSWORD {}").format(sql.Literal(password)))
            target.execute("CREATE ROLE old_worker NOLOGIN PASSWORD NULL")
            identity = target.execute(
                "SELECT jsonb_build_object('cluster',system_identifier::text,"
                "'database',current_database(),'database_oid',(SELECT oid::bigint "
                "FROM pg_database WHERE datname=current_database())) FROM pg_control_system()"
            ).fetchone()[0]
        with psycopg.connect(**source_options, autocommit=True) as source:
            source.execute("INSERT INTO observed VALUES(1),(2)")
        backup = temporary / "final.dump"
        run(
            "pg_dump",
            "-h",
            str(temporary / "primary-socket"),
            "-p",
            str(source_options["port"]),
            "-U",
            "postgres",
            "-Fc",
            "-f",
            str(backup),
            "postgres",
        )
        run(
            "pg_restore",
            "--exit-on-error",
            "--single-transaction",
            "-h",
            str(socket),
            "-p",
            str(number),
            "-U",
            "postgres",
            "-d",
            "postgres",
            str(backup),
        )
        backup.unlink()
        with psycopg.connect(**control_options, autocommit=True) as control:
            store = Store(control, control_config["identity"], control_config["old_logins"])
            with control.transaction():
                snapshot = runtime.state(store, config["runtime"]["deployment_id"])
        inspected = {
            "version": 1,
            "operation_id": str(uuid4()),
            "services": config["services"],
            "fence": {
                "deployment_id": snapshot["parent"]["deployment_id"],
                "operation_id": snapshot["parent"]["operation_id"],
                "revision": snapshot["parent"]["revision"],
                "state_sha256": runtime.digest(snapshot),
            },
            "stores": [
                *copy.deepcopy(config["stores"]),
                {
                    "kind": "primary",
                    "identity": identity,
                    "old_logins": ["old_worker"],
                    "connection": source_config["connection"] | {"port": number},
                },
            ],
        }
        assert "activation not authorized" in install_and_run("restore-normal")
        result = json.loads(
            run("sudo", "-n", "cat", str(private / "restore-normal/comparison.json"))
        )
        assert result["content"]["rows"] == 2
        assert result["activationAuthorized"] is False
        conditions.append("actual peer/TLS/three-cluster backup equality")
        with psycopg.connect(**target_options, autocommit=True) as target:
            target.execute("DELETE FROM observed WHERE value=2")
        install_and_run("restore-stale", success=False)
        with psycopg.connect(**target_options, autocommit=True) as target:
            target.execute("INSERT INTO observed VALUES(2)")
        conditions.append("stale target refused")
        with psycopg.connect(**target_options, autocommit=True) as target:
            target.execute(
                "CREATE SUBSCRIPTION restore_fixture CONNECTION "
                "'host=127.0.0.1 port=9 dbname=absent user=absent' "
                "PUBLICATION absent WITH "
                "(connect=false,create_slot=false,enabled=false,slot_name=NONE)"
            )
        try:
            install_and_run("restore-subscription", success=False)
        finally:
            with psycopg.connect(**target_options, autocommit=True) as target:
                target.execute("DROP SUBSCRIPTION restore_fixture")
        conditions.append("logical subscription outside service inventory refused")
        with psycopg.connect(**source_options, autocommit=True):
            install_and_run("restore-concurrent", success=False)
        conditions.append("concurrent source administrator refused")
        selected = inspected["fence"]["state_sha256"]
        inspected["fence"]["state_sha256"] = "0" * 64
        install_and_run("restore-fence", success=False)
        inspected["fence"]["state_sha256"] = selected
        conditions.append("wrong fence digest refused")
        unit_path = Path("/run/systemd/system") / inspected["services"][0]
        original_unit = run("sudo", "-n", "cat", str(unit_path))
        assert "User=nobody" in original_unit
        changed_unit = temporary / "restore-peer-identity.service"
        changed_unit.write_text(original_unit.replace("User=nobody", "User=" + os.environ["USER"]))
        try:
            run("sudo", "-n", "install", "-m", "644", str(changed_unit), str(unit_path))
            run("sudo", "-n", "systemctl", "daemon-reload")
            install_and_run("restore-peer-identity", success=False)
        finally:
            changed_unit.write_text(original_unit)
            run("sudo", "-n", "install", "-m", "644", str(changed_unit), str(unit_path))
            run("sudo", "-n", "systemctl", "daemon-reload")
        conditions.append("worker with control administrator OS identity refused")
        inspected["stores"][1], inspected["stores"][2] = (
            inspected["stores"][2],
            inspected["stores"][1],
        )
        install_and_run("restore-source", success=False)
        inspected["stores"][1], inspected["stores"][2] = (
            inspected["stores"][2],
            inspected["stores"][1],
        )
        conditions.append("restored target cannot substitute for current source")
        if args.cutover_cli:
            from cutover_prepare_entry import entry as prepare_entry  # noqa: PLC0415

            conditions.extend(
                prepare_entry(temporary, config, inspected, args, private, certificate, key)
            )
        else:
            # The packaged primitives are exercised by two distinct root processes.
            # No runtime entry or product activation capability is introduced here.
            plan_config = temporary / "cutover-plan-config.json"
            plan_config.write_text(
                json.dumps(
                    {
                        "inspection": inspected,
                        "names": [
                            {
                                name: name.replace("old_", "fresh_", 1)
                                for name in store["old_logins"]
                            }
                            for store in [inspected["stores"][0], inspected["stores"][2]]
                        ],
                        "redis": {"name": "fresh_worker", "commands": ["get", "set", "ping"]},
                    }
                )
            )
            plan_config.chmod(0o600)
            run(
                "sudo", "-n", "install", "-m", "600", str(plan_config), str(private / "plan-config")
            )
            run(
                "sudo",
                "-n",
                "install",
                "-m",
                "600",
                str(Path(__file__).with_name("cutover_plan.py")),
                str(private / "plan-probe.py"),
            )
            for flags in [[], ["--resume"]]:
                probe_output = run(
                    "sudo",
                    "-n",
                    sys.executable,
                    "-E",
                    "-s",
                    str(private / "plan-probe.py"),
                    "--operator",
                    str(args.operator),
                    "--config",
                    str(private / "plan-config"),
                    "--directory",
                    str(private / "cutover-plan"),
                    *flags,
                )
                assert "no activation" in probe_output or "all credentials disabled" in probe_output
            conditions.append(
                "two root processes retain secrets and reconcile partial SQL replacement"
            )
        # An actual primary restart must not be accepted as the pinned source incarnation.
        run("pg_ctl", "-D", str(temporary / "primary"), "-m", "fast", "-w", "stop")
        install_and_run("restore-source-unavailable", success=False)
        run(
            "sudo",
            "-n",
            "test",
            "-e",
            str(private / "restore-source-unavailable" / "comparison.json"),
            success=False,
        )
        with psycopg.connect(**control_options, autocommit=True) as control:
            store = Store(control, control_config["identity"], control_config["old_logins"])
            with control.transaction():
                assert runtime.state(store, config["runtime"]["deployment_id"]) == snapshot
        conditions.append(
            "unavailable source refuses without comparison receipt or control changes"
        )
        run(
            "pg_ctl",
            "-D",
            str(temporary / "primary"),
            "-l",
            str(args.output / "primary-restart.log"),
            "-w",
            "start",
        )
        install_and_run("restore-restarted", success=False)
        conditions.append("actual source restart refused; old control checkpoint unchanged")
        with psycopg.connect(**control_options, autocommit=True) as control:
            store = Store(control, control_config["identity"], control_config["old_logins"])
            with control.transaction():
                assert runtime.state(store, config["runtime"]["deployment_id"]) == snapshot
        result["conditions"] = conditions
        (args.output / "restore-inspect-result.json").write_text(
            json.dumps(result, indent=2) + "\n"
        )
        return conditions
    finally:
        run("pg_ctl", "-D", str(data), "-m", "immediate", "-w", "stop")
