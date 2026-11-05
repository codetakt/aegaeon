"""Actual packaged preparation with old/new TLS Redis and independent SQL stores."""

from __future__ import annotations

import copy
import json
import secrets
import socket
import subprocess
import time

import psycopg
from recovery_entry import port, run


def entry(temporary, runtime_config, inspected, args, private, certificate, key):  # noqa: PLR0912,PLR0913,PLR0917,PLR0915
    from organization_recovery_redis import info, pairs  # noqa: PLC0415
    from organization_recovery_resp import Resp  # noqa: PLC0415

    data = temporary / "cutover-redis"
    data.mkdir(mode=0o700)
    number, password = port(), secrets.token_hex(32)
    secret = temporary / "cutover-redis-password"
    secret.write_text(password)
    assert secret.stat().st_mode & 0o777 == 0o600, "secret readable before chmod"
    secret.chmod(0o600)
    run("sudo", "-n", "install", "-m", "600", str(secret), str(private / "cutover-redis-password"))
    acl = data / "users.acl"
    acl.write_text(f"user admin on >{password} ~* &* +@all\nuser default off resetpass -@all\n")
    acl.chmod(0o600)
    configuration = data / "redis.conf"
    configuration.write_text(
        f"bind 127.0.0.1\nport 0\ntls-port {number}\ntls-cert-file {certificate}\n"
        f"tls-key-file {key}\ntls-ca-cert-file {certificate}\ntls-auth-clients no\n"
        f'aclfile {acl}\ndir {data}\nappendonly yes\nappendfsync always\nsave ""\ndatabases 16\n'
    )
    with (args.output / "cutover-redis.log").open("wb") as log:
        server = subprocess.Popen(["redis-server", str(configuration)], stdout=log, stderr=log)  # noqa: S603,S607

    def connect():
        return Resp("localhost", number, certificate.read_text(), "admin", password)

    passed = []
    try:
        deadline = time.monotonic() + 10
        while True:
            assert server.poll() is None
            try:
                with socket.create_connection(("127.0.0.1", number), timeout=0.1):
                    break
            except OSError:
                assert time.monotonic() < deadline
                time.sleep(0.02)
        link = connect()
        try:
            identity = {"run_id": info(link.call("INFO", "server"))["run_id"], "database": 0}
            link.call("SELECT", "15")
            link.call("SET", "retained", "root")
        finally:
            link.close()
        config = {
            "inspection": inspected,
            "names": [
                {name: name.replace("old_", "fresh_", 1) for name in store["old_logins"]}
                for store in [inspected["stores"][0], inspected["stores"][2]]
            ],
            "redis": {"name": "fresh_worker", "commands": ["get", "set", "ping"]},
            "preparation": {
                "version": 1,
                "retired_token": runtime_config["token"],
                "destination_token": {
                    "identity": identity,
                    "old_logins": ["default"],
                    "connection": runtime_config["token"]["connection"]
                    | {
                        "port": number,
                        "password_file": str(private / "cutover-redis-password"),
                    },
                },
            },
        }

        def invoke(value, *, success=True):
            path = temporary / "cutover-config.json"
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            run("sudo", "-n", "install", "-m", "600", str(path), str(private / "cutover-config"))
            return run(
                "sudo",
                "-n",
                str(args.operator / "bin/aegaeon-organization-cutover-prepare"),
                "--config",
                str(private / "cutover-config"),
                "--directory",
                str(private / "cutover"),
                success=success,
            )

        def step():
            value = inspected["stores"][0]["connection"]
            with psycopg.connect(
                host=value["socket"], port=value["port"], dbname=value["dbname"], user=value["user"]
            ) as connection:
                return connection.execute(
                    "SELECT step FROM organization_witness.cutover_operations "
                    "WHERE deployment_id=%s AND operation_id=%s",
                    (inspected["fence"]["deployment_id"], inspected["operation_id"]),
                ).fetchone()[0]

        invoke(config, success=False)
        assert step() == 0
        passed.append("packaged entry refuses retained token data in DB15")
        link = connect()
        try:
            link.call("SELECT", "15")
            link.call("DEL", "retained")
        finally:
            link.close()
        data.chmod(0o500)
        try:
            invoke(config, success=False)
            assert step() == 4
        finally:
            data.chmod(0o700)
        result = json.loads(invoke(config))
        assert result["step"] == 5
        assert result["activationAuthorized"] is False
        assert json.loads(invoke(config)) == result
        passed.append("packaged entry resumes SQL-complete ACL-save failure with same plan")
        passed.append("completed preparation replay stays disabled and stable")
        changed = copy.deepcopy(config)
        changed["redis"]["commands"].append("del")
        invoke(changed, success=False)
        changed = copy.deepcopy(config)
        changed["preparation"]["retired_token"]["identity"]["run_id"] = "0" * 40
        invoke(changed, success=False)
        passed.append("changed plan and false retired-token incarnation refused")
        link = connect()
        try:
            for index in range(16):
                link.call("SELECT", str(index))
                assert link.call("DBSIZE") == 0
            profile = pairs(link.call("ACL", "GETUSER", "fresh_worker"))
            assert "off" in profile["flags"]
            assert len(profile["passwords"]) == 1
        finally:
            link.close()
        (args.output / "cutover-prepare-result.json").write_text(
            json.dumps(
                {
                    "status": "passed",
                    "conditions": passed,
                    "result": result,
                    "actual_stores": (
                        "independent control/current/target SQL plus retired/fresh TLS Redis"
                    ),
                    "native_validation": False,
                    "activation": False,
                    "newCompositeDischarges": 0,
                },
                indent=2,
            )
            + "\n"
        )
        return passed
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
