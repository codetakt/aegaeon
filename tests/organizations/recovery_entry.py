"""Owned root CLI/TLS/system-service fixture, never a production custody claim."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql


def run(*args, success=True, timeout=135):
    result = subprocess.run(  # noqa: S603 — fixed fixture tools, all paths are owned
        args, check=False, capture_output=True, text=True, timeout=timeout
    )
    assert (result.returncode == 0) == success, (args[0], result.stdout, result.stderr)
    return result.stdout


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def peer_refusals(temporary, config, operator, private, *, password, certificate):  # noqa: PLR0913
    value = config["stores"][0]["connection"]
    with pytest.raises(psycopg.OperationalError, match=r"pg_hba\.conf"):
        psycopg.connect(
            host="localhost",
            port=value["port"],
            dbname="postgres",
            user="postgres",
            password=password,
            sslmode="verify-full",
            sslrootcert=str(certificate),
            connect_timeout=2,
        )
    # Allow the deliberately wrong OS identity to reach the socket. The server
    # kernel-identity check, rather than a parent directory denial, must reject.
    temporary.chmod(0o711)
    probe = temporary / "peer-probe.py"
    probe.write_text(
        "import os,sys\n"
        f"sys.path.insert(0,{str(operator / 'share/aegaeon/scripts/operations')!r})\n"
        "from organization_recovery_peer import peer_connection\n"
        f"value={value!r}\n"
        "before=(os.geteuid(),os.getegid(),os.getgroups())\n"
        "for change in ({'socket':value['socket']+'/missing'},{'peer_user':'nobody'}):\n"
        "    try:\n"
        "        peer_connection(value|change,'-c statement_timeout=1000')\n"
        "    except Exception as error:\n"
        "        if 'peer_user' in change: assert 'requirepeer' in str(error)\n"
        "    else: raise AssertionError('unsafe peer accepted')\n"
        "    assert before==(os.geteuid(),os.getegid(),os.getgroups())\n"
        "print('peer refusal and OS identity restoration passed')\n"
    )
    run("sudo", "-n", "install", "-m", "600", str(probe), str(private / "peer-probe.py"))
    result = run("sudo", "-n", sys.executable, "-E", "-s", str(private / "peer-probe.py"))
    assert result.strip() == "peer refusal and OS identity restoration passed"


def root_entry(temporary, stores, config, args):  # noqa: PLR0912, PLR0915 — ordered owned fixture
    operator, output, peer = args.operator, args.output, args.peer_cli
    name = "aegaeon-organization-maintenance-test-" + uuid4().hex
    unit = name + ".service"
    private = Path("/run") / name
    unit_path = Path("/run/systemd/system") / unit
    password = secrets.token_urlsafe(32)
    password_file = temporary / "admin-password"
    password_file.write_text(password)
    password_file.chmod(0o600)
    certificate, key = temporary / "server.crt", temporary / "server.key"
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost",
        "-keyout",
        str(key),
        "-out",
        str(certificate),
    )
    key.chmod(0o600)
    try:
        for store, configured in zip(stores, config["stores"], strict=True):
            kind = configured["kind"]
            store.connection.execute(
                sql.SQL("ALTER ROLE postgres PASSWORD {}").format(sql.Literal(password))
            )
            store.connection.close()
            run("pg_ctl", "-D", str(temporary / kind), "-w", "-t", "10", "-m", "fast", "stop")
            number = port()
            if peer and kind == "control":
                (temporary / kind / "pg_hba.conf").write_text(
                    "local all postgres peer map=owned_recovery\nlocal all all reject\n"
                    "host all postgres 0.0.0.0/0 reject\n"
                    "hostssl all old_worker 127.0.0.1/32 scram-sha-256\n"
                    "host all all 0.0.0.0/0 reject\n"
                )
                (temporary / kind / "pg_ident.conf").write_text(
                    f"owned_recovery {os.environ['USER']} postgres\n"
                )
            else:
                (temporary / kind / "pg_hba.conf").write_text(
                    "local all all trust\nhostssl all all 127.0.0.1/32 scram-sha-256\n"
                    "host all all 0.0.0.0/0 reject\n"
                )
            with (temporary / kind / "postgresql.conf").open("a") as handle:
                handle.write(
                    f"\nlisten_addresses='127.0.0.1'\nport={number}\nssl=on\n"
                    f"ssl_cert_file='{certificate}'\nssl_key_file='{key}'\n"
                    f"unix_socket_directories='{temporary / (kind + '-socket')}'\n"
                )
            run(
                "pg_ctl",
                "-D",
                str(temporary / kind),
                "-l",
                str(output / (kind + "-tls.log")),
                "-w",
                "-t",
                "10",
                "start",
            )
            configured["connection"].update(
                port=number, password_file=str(private / "password"), ca_file=str(private / "ca")
            )
            if peer and kind == "control":
                configured["connection"] = {
                    "socket": str(temporary / "control-socket"),
                    "port": number,
                    "dbname": "postgres",
                    "user": "postgres",
                    "peer_user": os.environ["USER"],
                }
        worker = temporary / "root-worker.py"
        worker.write_text(
            "import os,time\nif os.fork() == 0:\n    time.sleep(120)\nelse:\n    time.sleep(120)\n"
        )
        unit_source = temporary / "worker.service"
        unit_source.write_text(
            "[Unit]\nDescription=Aegaeon owned root recovery fixture\n[Service]\nType=simple\n"
            f"User={os.environ['USER']}\nKillMode=control-group\nDelegate=no\nSendSIGKILL=yes\n"
            f"TimeoutStopSec=3\nExecStart={sys.executable} {worker}\n"
        )
        if peer:
            # Separate from the database OS identity; no newly provisioned user
            # or editable privileged script is needed for this bounded worker.
            unit_source.write_text(
                "[Unit]\nDescription=Aegaeon owned peer recovery fixture\n[Service]\n"
                "Type=simple\nUser=nobody\nKillMode=control-group\nDelegate=no\n"
                "SendSIGKILL=yes\nTimeoutStopSec=3\n"
                f'ExecStart={sys.executable} -c "import os,time; os.fork(); time.sleep(120)"\n'
            )
        with unit_source.open("a") as handle:
            handle.write("NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n")
        run("sudo", "-n", "install", "-d", "-m", "700", str(private))
        for source, destination in [
            (password_file, private / "password"),
            (certificate, private / "ca"),
        ]:
            run("sudo", "-n", "install", "-m", "600", str(source), str(destination))
        run("sudo", "-n", "install", "-m", "644", str(unit_source), str(unit_path))
        run("sudo", "-n", "systemctl", "daemon-reload")
        run("sudo", "-n", "systemctl", "start", unit)
        config["services"] = [unit]
        if args.runtime_cli:
            from runtime_recovery_entry import entry  # noqa: PLC0415

            return entry(
                temporary,
                config,
                args,
                private,
                password=password,
                certificate=certificate,
                key=key,
            )
        config_file = temporary / "root-config.json"
        config_file.write_text(json.dumps(config))
        config_file.chmod(0o600)
        run("sudo", "-n", "install", "-m", "600", str(config_file), str(private / "config"))
        if peer:
            peer_refusals(
                temporary, config, operator, private, password=password, certificate=certificate
            )
        executable = str(operator / "bin/aegaeon-organization-recovery")
        arguments = ["--config", str(private / "config"), "--output", str(private / "receipt")]
        run(executable, *arguments, success=False)
        message = run("sudo", "-n", executable, *arguments)
        assert "activation not authorized" in message
        assert run("sudo", "-n", executable, *arguments, "--inspect").strip() == "completed"
        # Repeating the mutation must not overwrite receipts or reacquire work.
        run("sudo", "-n", executable, *arguments, success=False)
        receipt = run("sudo", "-n", "cat", str(private / "receipt/reconciliation.json"))
        result = run("sudo", "-n", "cat", str(private / "receipt/released.json"))
        assert (
            hashlib.sha256(receipt.encode()).hexdigest() == json.loads(result)["completion_sha256"]
        )
        assert json.loads(receipt)["activationAuthorized"] is False
        (output / "root-reconciliation.json").write_text(receipt)
        (output / "root-released.json").write_text(result)
        return {
            "packaged_root_cli": True,
            "actual_tls_admin_connections": True,
            "local_control_peer": peer,
            "peer_failure_identity_restoration": peer,
            "administrator_tcp_refused": peer,
            "actual_system_service_with_child": True,
            "nonroot_refused": True,
            "read_only_completion": "completed",
            "mutation_overwrite_refused": True,
            "operator": str(operator),
            "supplier_qualified": False,
            "activation": False,
        }
    finally:
        if unit_path.exists():
            run("sudo", "-n", "systemctl", "stop", unit)
            run("sudo", "-n", "rm", "--", str(unit_path))
            run("sudo", "-n", "systemctl", "daemon-reload")
        if private.exists():
            # Only the exact UUID-named fixture created above is removed.
            run("sudo", "-n", "rm", "-r", "--", str(private))
