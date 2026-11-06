"""Actual TLS Redis exclusion, persistence, queued work and retained failures."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout  # noqa: S603


def main():  # noqa: C901,PLR0915 — one owned, ordered lifecycle
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cutover", action="store_true")
    args = parser.parse_args()
    source = args.operator / "share/aegaeon/scripts/operations"
    sys.path.insert(0, str(source))
    from organization_recovery_redis import RedisStore, info  # noqa: PLC0415
    from organization_recovery_resp import Resp  # noqa: PLC0415

    args.output.mkdir(mode=0o700)
    temporary = Path(tempfile.mkdtemp(prefix="aegaeon-redis-recovery-"))
    server = None
    connections = []
    passed = []
    try:
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
        ca = certificate.read_text()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        admin_password, worker_password = secrets.token_hex(32), secrets.token_hex(32)
        acl = temporary / "users.acl"
        acl.write_text(
            f"user admin on >{admin_password} ~* &* +@all\n"
            "user default off resetpass -@all\n"
            + (
                ""
                if args.cutover
                else f"user worker on >{worker_password} ~* +get +set +multi +exec +ping\n"
            )
        )
        acl.chmod(0o600)
        config = temporary / "redis.conf"
        config.write_text(
            f"bind 127.0.0.1\nport 0\ntls-port {port}\ntls-cert-file {certificate}\n"
            f"tls-key-file {key}\ntls-ca-cert-file {certificate}\ntls-auth-clients no\n"
            f"aclfile {acl}\ndir {temporary}\nappendonly yes\nappendfsync always\n"
            'save ""\ndatabases 16\n'
        )

        def start():
            log = (args.output / "redis.log").open("ab")
            try:
                process = subprocess.Popen(["redis-server", str(config)], stdout=log, stderr=log)  # noqa: S603,S607 — pinned fixture tool
            finally:
                log.close()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                assert process.poll() is None
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        return process
                except OSError:
                    time.sleep(0.02)
            process.terminate()
            process.wait(timeout=10)
            pytest.fail("owned Redis startup deadline")

        def connection(user="admin", password=admin_password):
            value = Resp("localhost", port, ca, user, password)
            connections.append(value)
            return value

        server = start()
        with pytest.raises(ssl.SSLCertVerificationError):
            Resp("127.0.0.1", port, ca, "admin", admin_password)
        admin = connection()
        identity = {"run_id": info(admin.call("INFO", "server"))["run_id"], "database": 0}
        if args.cutover:
            from cutover_token import scenario  # noqa: PLC0415

            def restart():
                nonlocal server
                for link in connections:
                    link.close()
                server.terminate()
                server.wait(timeout=10)
                server = start()
                active = connection()
                selected = {"run_id": info(active.call("INFO", "server"))["run_id"], "database": 0}
                return RedisStore(active, selected, "admin", ["default"])

            scenario(
                RedisStore(admin, identity, "admin", ["default"]),
                connection,
                restart,
                temporary,
                args.output,
            )
            return
        store = RedisStore(admin, identity, "admin", ["default", "worker"])
        (args.output / "supplier.json").write_text(
            json.dumps(
                {
                    "configuration": admin.call(
                        "CONFIG", "GET", "appendfsync", "aclfile", "databases"
                    ),
                    "modules": admin.call("MODULE", "LIST"),
                },
                indent=2,
            )
            + "\n"
        )
        store.check()
        with pytest.raises(Exception, match="credentials remain usable"):
            store.drain()
        passed.append("usable credentials refuse drain")
        wrong = RedisStore(admin, identity | {"run_id": "0" * 40}, "admin", store.old_logins)
        with pytest.raises(Exception, match="identity"):
            wrong.check()
        admin.call("ACL", "SETUSER", "unexpected", "off")
        with pytest.raises(Exception, match="unlisted"):
            store.check()
        admin.call("ACL", "DELUSER", "unexpected")
        admin.call("ACL", "SETUSER", "worker", "+acl|setuser")
        with pytest.raises(Exception, match="escape credential"):
            store.check()
        admin.call("ACL", "SETUSER", "worker", "-acl|setuser")
        admin.call("ACL", "SETUSER", "worker", "(+get ~*)")
        with pytest.raises(Exception, match="selectors"):
            store.check()
        admin.call("ACL", "SETUSER", "worker", "clearselectors")
        # A subcommand grant/revoke can normalize to category/subcommand rules.
        # Reinstall the exact known fixture before testing unrelated boundaries.
        admin.call(
            "ACL",
            "SETUSER",
            "worker",
            "reset",
            "on",
            ">" + worker_password,
            "~*",
            "+get",
            "+set",
            "+multi",
            "+exec",
            "+ping",
        )
        store.check()
        admin.call("CONFIG", "SET", "appendfsync", "everysec")
        with pytest.raises(Exception, match="persistence"):
            store.check()
        admin.call("CONFIG", "SET", "appendfsync", "always")
        passed.append(
            "wrong identity, extra login, privileged command, selector and weak durability refused"
        )

        # Same refusal assertion must detect removing the actual exclusion check.
        text = (source / "organization_recovery_redis.py").read_text()
        assert text.count("self.check(excluded=True)") == 3
        mutant_path = args.output / "redis-guard-mutant.py"
        mutant_path.write_text(
            text.replace("self.check(excluded=True)", "self.check(excluded=False)")
        )
        spec = importlib.util.spec_from_file_location("redis_guard_mutant", mutant_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        mutant = module.RedisStore(admin, identity, "admin", store.old_logins)
        with (
            pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"),
            pytest.raises(Exception, match="credentials remain usable"),
        ):
            mutant.drain()
        passed.append("credential guard omission detected by identical refusal assertion")

        worker = connection("worker", worker_password)
        assert worker.call("SET", "committed-before-stop", "retained") == "OK"
        assert worker.call("MULTI") == "OK"
        assert worker.call("SET", "uncommitted-at-stop", "must-not-appear") == "QUEUED"
        # Make ACL SAVE fail after in-memory exclusions. Restore only the owned
        # directory's access, not old credentials; retry requires a fresh link.
        temporary.chmod(0o500)
        with pytest.raises(Exception, match="Redis command refused"):
            store.exclude()
        temporary.chmod(0o700)
        assert admin.failed
        admin = connection()
        store = RedisStore(admin, identity, "admin", store.old_logins)
        store.check(excluded=True)
        store.exclude()
        passed.append("failed ACL persistence invalidates link and retains in-memory exclusion")
        other = connection()
        with pytest.raises(Exception, match="unexpected Redis client"):
            store.drain()
        other.close()
        result = store.drain()
        assert len(result["terminated_clients"]) >= 1
        assert admin.call("GET", "committed-before-stop") == "retained"
        assert admin.call("GET", "uncommitted-at-stop") is None
        with pytest.raises(Exception, match=r"Redis reply|closed|reset|broken pipe"):
            worker.call("EXEC")
        with pytest.raises(Exception, match="Redis command refused"):
            connection("worker", worker_password)
        passed.append(
            "clients terminated and queued transaction discarded; committed data/reconnect checks"
        )
        for item in connections:
            item.close()
        server.terminate()
        server.wait(timeout=10)
        server = start()
        admin = connection()
        new_identity = {"run_id": info(admin.call("INFO", "server"))["run_id"], "database": 0}
        assert new_identity != identity
        with pytest.raises(Exception, match="identity"):
            RedisStore(admin, identity, "admin", store.old_logins).check(excluded=True)
        RedisStore(admin, new_identity, "admin", store.old_logins).check(excluded=True)
        assert admin.call("GET", "committed-before-stop") == "retained"
        assert admin.call("GET", "uncommitted-at-stop") is None
        with pytest.raises(Exception, match="Redis command refused"):
            connection("worker", worker_password)
        passed.append("restart preserves ACL exclusion/data; old process identity refuses")
        from recovery_protocol import refusals  # noqa: PLC0415 — owned TLS fault peers

        protocol = refusals(certificate, key, Resp)
        (args.output / "result.json").write_text(
            json.dumps(
                {
                    "operator": str(args.operator),
                    "redis_version": info(admin.call("INFO", "server"))["redis_version"],
                    "passed": passed,
                    "tls_hostname_refused": True,
                    "protocol_faults": protocol,
                    "pending_release": False,
                    "activation": False,
                    "production_supplier_qualified": False,
                    "new_atomic_discharge": 0,
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        temporary.chmod(0o700)
        for item in connections:
            item.close()
        if server is not None and server.poll() is None:
            server.terminate()
            server.wait(timeout=10)
        if server is None or server.poll() is not None:
            shutil.rmtree(temporary)


if __name__ == "__main__":
    main()
