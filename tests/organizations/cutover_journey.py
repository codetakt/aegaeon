"""Actual native cutover validation on three SQL stores and two TLS Redis stores."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from history_journey import empty_history, identity as tool_identity, prepare, tree_identity
from history_restoration import setup as history_setup, target as history_target
from recovery_entry import port, run as root_run


def modules(root):
    path = str(root / "tests/organizations/legacy_operations")
    if path not in sys.path:
        sys.path.insert(0, path)


def configure_retired_token(root, directory, configuration, password):
    modules(root)
    from organization_recovery_redis import WORKER_COMMANDS  # noqa: PLC0415

    admin = secrets.token_urlsafe(32)
    (directory / "token-admin-password").write_text(admin)
    (directory / "token-admin-password").chmod(0o600)
    acl = directory / "retired-users.acl"
    acl.write_text(
        f"user default off resetpass -@all\nuser admin on >{admin} ~* &* +@all\n"
        f"user runtime on >{password} ~* -@all "
        + " ".join("+" + command for command in sorted(WORKER_COMMANDS))
        + "\n"
    )
    acl.chmod(0o600)
    lines = [
        line for line in configuration.read_text().splitlines() if not line.startswith("user ")
    ]
    configuration.write_text("\n".join(lines) + f"\naclfile {acl}\n")


def prepare_additional(sql, config):
    """Fence every additional real namespace and retain its empty history."""
    deployment = UUID(config["deployment_id"])
    for item in config["environments"][1:]:
        environment, operation = UUID(item["id"]), uuid4()
        child = json.loads(
            sql(
                "control",
                f"SELECT organization_witness.current_state('{environment}','{deployment}')",
            )
        )
        child = json.loads(
            sql(
                "control",
                "SELECT organization_witness.fence("
                f"'{environment}','{deployment}','{operation}',{child['revision']})",
            )
        )
        issuer = urlsplit(item["issuer"]).hostname
        assert issuer
        assert "'" not in issuer
        empty_history(sql, (environment, deployment, operation, child["revision"]), issuer)


def retain_serving_fixture(directory, args, root, retain):
    if not args.serving_case:
        return
    retain("serving-case.json", json.dumps({"mode": args.serving_case}))
    retain("bootstrap.json", (directory / "bootstrap.json").read_text())
    for name in (
        "cutover_serving_probe.py",
        "cutover_forward_probe.py",
        "cutover_forward_store.py",
        "cutover_forward_workers.py",
        "delivery_journey.py",
        "delivery_adapter.py",
    ):
        retain(name, (root / "tests/organizations" / name).read_text())


def journey(directory, args, helpers, report):  # noqa: PLR0912,PLR0915 — finite owned supplier lifecycle
    root, env, run, sql, setup, cluster, clusters = helpers
    modules(root)
    from organization_recovery_redis import WORKER_COMMANDS  # noqa: PLC0415

    private = Path("/run") / ("aegaeon-organization-native-" + uuid4().hex)
    unit = "aegaeon-organization-runtime-native-" + uuid4().hex + ".service"
    unit_path = Path("/run/systemd/system") / unit
    tokens = []
    fixture = json.loads((directory / "fixture.json").read_text())
    config = json.loads((directory / "runtime.json").read_text())
    if args.epoch_coordinator:
        assert len(config["environments"]) == 2, "complete real two-Environment fixture required"
    scope = prepare(sql, config, **history_setup(directory, config))
    prepare_additional(sql, config)
    restore_facts(directory, args, (root, env, run), scope)
    primary = urlsplit(fixture["primary"])
    database = primary.path.removeprefix("/")
    sql("primary", "CHECKPOINT", database)
    cluster("destination")
    roles = setup(
        [args.postgres_bin / "pg_dumpall", "--roles-only"], environment=clusters["primary"]["env"]
    )
    roles = "\n".join(line for line in roles.splitlines() if line != "CREATE ROLE postgres;")
    setup(
        [args.postgres_bin / "psql", "-Xq", "-v", "ON_ERROR_STOP=1"],
        environment=clusters["destination"]["env"],
        data=roles,
    )
    dump = directory / "current.dump"
    setup(
        [args.postgres_bin / "pg_dump", "-Fc", "--file", dump],
        environment=clusters["primary"]["env"] | {"PGDATABASE": database},
    )
    dump.chmod(0o600)
    setup(
        [
            args.postgres_bin / "pg_restore",
            "--exit-on-error",
            "--create",
            "--dbname=postgres",
            dump,
        ],
        environment=clusters["destination"]["env"],
    )
    sql("destination", "CHECKPOINT", database)
    catalogs = {
        kind: json.loads(sql(kind, "SELECT aegaeon.subject_history_observed_physical()", database))
        for kind in ("primary", "destination")
    }
    for kind, value in catalogs.items():
        (args.output / (kind + "-physical.json")).write_text(json.dumps(value, indent=2))
    assert catalogs["primary"] == catalogs["destination"], "restored physical catalog differs"
    root_run("sudo", "-n", "mkdir", "-m", "700", str(private))
    try:

        def retain(name, data):
            path = directory / ("root-" + name)
            path.write_bytes(data if isinstance(data, bytes) else data.encode())
            path.chmod(0o600)
            root_run("sudo", "-n", "install", "-m", "600", str(path), str(private / name))
            return str(private / name)

        unit_source = retain(
            "worker.service",
            "[Service]\nType=simple\nExecStart=/bin/true\n"
            f"User={os.getuid()}\nKillMode=control-group\nSendSIGKILL=yes\nDelegate=no\n"
            "NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n",
        )
        root_run("sudo", "-n", "install", "-m", "644", unit_source, str(unit_path))
        root_run("sudo", "-n", "systemctl", "daemon-reload")
        ca = retain("ca", (directory / "trusted.crt").read_text())
        key = retain("kek", env["AEGAEON_KEY_ENCRYPTION_KEY"])
        admin_password = secrets.token_urlsafe(32)
        secret = retain("sql-password", admin_password)
        stores = []
        for kind, db in [("control", "postgres"), ("primary", database), ("destination", database)]:
            sql(kind, f"ALTER ROLE postgres PASSWORD '{admin_password}'", db)
            names = json.loads(
                sql(
                    kind,
                    "SELECT jsonb_agg(rolname ORDER BY rolname) "
                    "FROM pg_roles WHERE rolcanlogin AND rolname<>'postgres'",
                    db,
                )
            )
            for name in names:
                assert name.replace("_", "").isalnum()
                sql(kind, f'ALTER ROLE "{name}" NOLOGIN PASSWORD NULL', db)
            identity = json.loads(
                sql(
                    kind,
                    "SELECT jsonb_build_object('cluster',system_identifier::text,"
                    "'database',current_database(),'database_oid',"
                    "(SELECT oid::bigint FROM pg_database WHERE datname=current_database())) "
                    "FROM pg_control_system()",
                    db,
                )
            )
            stores.append(
                {
                    "kind": "control" if kind == "control" else "primary",
                    "identity": identity,
                    "old_logins": names,
                    "connection": {
                        "host": "localhost",
                        "port": clusters[kind]["port"],
                        "dbname": db,
                        "user": "postgres",
                        "password_file": secret,
                        "ca_file": ca,
                    },
                }
            )
        token, old, new = token_stores(directory, args, fixture, retain)
        tokens.append(token)
        if args.serving_case == "forward":
            cluster("successor")
            sql("successor", f"ALTER ROLE postgres PASSWORD '{admin_password}'")
            successor = {
                "host": "localhost",
                "port": clusters["successor"]["port"],
                "dbname": database,
                "user": "postgres",
                "password_file": secret,
                "ca_file": ca,
            }
            later, successor_token = fresh_token(directory, args, retain, "successor-token")
            tokens.append(later)
            retain("pre-write.dump", dump.read_bytes())
            retain(
                "forward-fixture.json",
                json.dumps(
                    {
                        "postgres_bin": str(args.postgres_bin),
                        "connection": successor,
                        "token": successor_token,
                    }
                ),
            )
        inspection = {
            "version": 1,
            "operation_id": str(uuid4()),
            "stores": stores,
            "services": [unit],
            "fence": {
                "deployment_id": str(scope[0]),
                "operation_id": str(scope[2]),
                "revision": scope[4]["revision"],
                "state_sha256": "0" * 64,
            },
        }
        native = {
            "version": 1,
            "control": {
                "host": "localhost",
                "port": clusters["control"]["port"],
                "database": "postgres",
            },
            "primary": {
                "host": "localhost",
                "port": clusters["destination"]["port"],
                "database": database,
            },
            "token": {"host": "localhost", "port": new["connection"]["port"]},
            "roles": {
                "control_runtime": "witness_runtime",
                "control_maintenance": "witness_maintenance",
                "primary_runtime": primary.username,
            },
            "root_cert_file": ca,
            "key_encryption_key_file": key,
            "environments": [
                {"id": item["id"], "issuer": item["issuer"]} for item in config["environments"]
            ],
        }
        configured = {
            "inspection": inspection,
            "names": [
                {name: "fresh_" + name for name in store["old_logins"]}
                for store in [stores[0], stores[2]]
            ],
            "redis": {"name": "fresh_worker", "commands": sorted(WORKER_COMMANDS)},
            "preparation": {"version": 1, "retired_token": old, "destination_token": new},
        }
        config_path = retain("config", json.dumps(configured))
        native_path = retain("native-config", json.dumps(native))
        inspect_root(directory, args, private, config_path)
        retain("probe.py", (root / "tests/organizations/cutover_validation_probe.py").read_text())
        retain("epoch-probe.py", (root / "tests/organizations/cutover_epoch_probe.py").read_text())
        retain(
            "epoch-coordinator.py",
            (root / "tests/organizations/cutover_epoch_coordinator.py").read_text(),
        )
        retain(
            "startup-probe.py", (root / "tests/organizations/startup_worker_probe.py").read_text()
        )
        retain(
            "startup-publication.py",
            (root / "tests/organizations/cutover_startup_probe.py").read_text(),
        )
        retain(
            "activation-probe.py",
            (root / "tests/organizations/cutover_activation_probe.py").read_text(),
        )
        retain_serving_fixture(directory, args, root, retain)
        observations = run_commands(args, private, config_path, native_path, retain, key, env)
        report["cutover_journey"] = {
            "passed": True,
            **observations,
            "activation": args.epoch_coordinator,
            "supplier_qualification": False,
            "newCompositeDischarges": 0,
        }
    except Exception:
        # Retain only stage names/exclusion completion in the public fixture
        # result. Secret plans and login verifiers stay in private custody.
        report["cutover_attempts"] = json.loads(
            root_run(
                "sudo",
                "-n",
                sys.executable,
                "-E",
                "-s",
                "-c",
                "import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); "
                "print(json.dumps([{'mode':json.loads(f.read_text())['mode'],"
                "'cleaned':(p/f.name.replace('attempt','cleanup')).exists()} "
                "for f in sorted(p.glob('validation-attempt-*.json'))]))",
                str(private / "plan"),
            )
        )
        raise
    finally:
        for token in reversed(tokens):
            token.terminate()
            try:
                token.wait(timeout=10)
            except subprocess.TimeoutExpired:
                token.kill()
                token.wait(timeout=5)
        root_run("sudo", "-n", "rm", "-f", str(unit_path))
        root_run("sudo", "-n", "systemctl", "daemon-reload")
        root_run("sudo", "-n", "rm", "-rf", str(private))


def token_stores(directory, args, fixture, retain):
    from organization_recovery_redis import info  # noqa: PLC0415
    from organization_recovery_resp import Resp  # noqa: PLC0415

    old_endpoint = urlsplit(fixture["token"])
    old_password = (directory / "token-admin-password").read_text()
    ca = (directory / "trusted.crt").read_text()
    old_link = Resp("localhost", old_endpoint.port, ca, "admin", old_password)
    try:
        old_link.call("ACL", "SETUSER", "runtime", "reset", "off")
        old_link.call("ACL", "SAVE")
        old_identity = {"run_id": info(old_link.call("INFO", "server"))["run_id"], "database": 3}
    finally:
        old_link.close()
    old = {
        "identity": old_identity,
        "old_logins": ["default", "runtime"],
        "connection": {
            "host": "localhost",
            "port": old_endpoint.port,
            "user": "admin",
            "ca_file": str(Path(retain("token-ca", ca))),
            "password_file": retain("old-token-password", old_password),
        },
    }
    server, new = fresh_token(directory, args, retain, "fresh-token")
    return server, old, new


def fresh_token(directory, args, retain, name):  # noqa: PLR0915 — finite token fixture lifecycle
    from organization_recovery_redis import info  # noqa: PLC0415
    from organization_recovery_resp import Resp  # noqa: PLC0415

    ca = (directory / "trusted.crt").read_text()
    data = directory / name
    data.mkdir(mode=0o700)
    number, password = port(), secrets.token_urlsafe(32)
    acl = data / "users.acl"
    acl.write_text(f"user default off resetpass -@all\nuser admin on >{password} ~* &* +@all\n")
    acl.chmod(0o600)
    configuration = data / "redis.conf"
    configuration.write_text(
        f"bind 127.0.0.1\nport 0\ntls-port {number}\ntls-cert-file {directory}/server.crt\n"
        f"tls-key-file {directory}/server.key\ntls-ca-cert-file {directory}/trusted.crt\n"
        "tls-auth-clients no\n"
        f'dir {data}\naclfile {acl}\nappendonly yes\nappendfsync always\nsave ""\ndatabases 16\n'
    )
    server = subprocess.Popen(  # noqa: S603 — owned fixture
        [str(args.redis_bin / "redis-server"), str(configuration)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
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
        link = Resp("localhost", number, ca, "admin", password)
        try:
            identity = {"run_id": info(link.call("INFO", "server"))["run_id"], "database": 3}
        finally:
            link.close()
        new = {
            "identity": identity,
            "old_logins": ["default"],
            "connection": {
                "host": "localhost",
                "port": number,
                "user": "admin",
                "ca_file": retain(name + "-ca", ca),
                "password_file": retain(name + "-password", password),
            },
        }
    except BaseException:
        server.terminate()
        server.wait(timeout=10)
        raise
    else:
        return server, new


def restore_facts(directory, args, helpers, scope):
    root, env, run = helpers
    deployment, environment, parent_op, child_op, parent, child = scope
    fixture = json.loads((directory / "fixture.json").read_text())
    executable, _, source, dirty = tool_identity(
        directory, args.server_package, tree_identity(root)
    )
    _, runtime, endpoint = history_target(directory)
    result = run(
        [
            executable,
            "--environment-id",
            str(environment),
            "--deployment-id",
            str(deployment),
            "--operation-id",
            str(child_op),
            "--expected-revision",
            str(child["revision"]),
            "--parent-operation-id",
            str(parent_op),
            "--parent-expected-revision",
            str(parent["revision"]),
            "--maintenance-work-id",
            str(uuid4()),
            "--root-cert",
            fixture["ca"],
            "--output-dir",
            directory / "restored-history",
            "--tool-source-record",
            source,
            "--dirty-input-record",
            dirty,
            "restore",
            "--target-runtime-role",
            runtime,
            "--restoration-operation-id",
            str(uuid4()),
        ],
        environment=env
        | {
            "AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": fixture["maintenance"],
            "AEGAEON_DATABASE_URL": endpoint,
        },
        timeout=40,
    )
    if result.returncode:
        message = "native source history restoration failed"
        raise RuntimeError(message)


def inspect_root(directory, args, private, config_path):
    operations = args.cutover_package / "share/aegaeon/scripts/operations"
    source = directory / "root-inspection.py"
    source.write_text(
        "import sys,json,os\nfrom contextlib import ExitStack\n"
        f"sys.path.insert(0,{str(operations)!r})\n"
        "import organization_recovery as r,organization_recovery_runtime as runtime\n"
        f"p={config_path!r}\nv=json.loads(r.private_file(p))\n"
        "with ExitStack() as stack:\n"
        " c=r.connect(stack,v['inspection']['stores'][0])\n"
        " with c.connection.transaction():\n"
        "  s=runtime.state(c,v['inspection']['fence']['deployment_id'])\n"
        " v['inspection']['fence']['state_sha256']=runtime.digest(s)\n"
        "with open(p,'w') as f:json.dump(v,f);f.flush();os.fsync(f.fileno())\n"
    )
    source.chmod(0o600)
    # Do not shadow Python's stdlib inspect module in the child script directory.
    helper = private / "fence_inspection.py"
    root_run("sudo", "-n", "install", "-m", "600", str(source), str(helper))
    root_run("sudo", "-n", sys.executable, "-E", "-s", str(helper))


def run_commands(args, private, config, native, retain, key, env):  # noqa: PLR0913,PLR0917,PLR0915 — exact private fixture selectors
    # Preparation uses the same copied package modules and retained journal.
    operations = args.cutover_package / "share/aegaeon/scripts/operations"
    prepared = json.loads(
        root_run(
            "sudo",
            "-n",
            sys.executable,
            "-E",
            "-s",
            str(operations / "organization_cutover_prepare.py"),
            "--config",
            config,
            "--directory",
            str(private / "plan"),
        )
    )
    assert prepared["step"] == 5
    command = [
        "sudo",
        "-n",
        str(args.cutover_package / "bin/aegaeon-organization-cutover-validate"),
        "--config",
        config,
        "--validation-config",
        native,
        "--directory",
        str(private / "plan"),
    ]
    result = json.loads(root_run(*command))
    assert result["step"] == 7
    assert result["activationAuthorized"] is False
    probe = [
        "sudo",
        "-n",
        sys.executable,
        "-E",
        "-s",
        str(private / "probe.py"),
        "--package",
        str(args.cutover_package),
        "--config",
        config,
        "--native",
        native,
        "--directory",
        str(private / "plan"),
    ]
    inspected = json.loads(root_run(*probe))
    assert inspected["historyMismatchRejected"] is True
    assert inspected["guardMutationDetected"] is True
    source = (operations / "organization_cutover_history.py").read_bytes()
    assert inspected["mutation"]["sourceSha256"] == hashlib.sha256(source).hexdigest()
    assert inspected["mutation"]["mutantSha256"] != inspected["mutation"]["sourceSha256"]
    root_run(*probe, "--abandon-lease", success=False)
    assert json.loads(root_run(*command)) == result
    retain("kek", secrets.token_urlsafe(32))
    root_run(*command, success=False)
    retain("kek", env["AEGAEON_KEY_ENCRYPTION_KEY"])
    assert key == str(private / "kek")
    assert json.loads(root_run(*command)) == result
    if args.epoch_coordinator:
        epoch_probe = [
            "sudo",
            "-n",
            sys.executable,
            "-E",
            "-s",
            str(private / "epoch-coordinator.py"),
            "--package",
            str(args.cutover_package),
            "--config",
            config,
            "--native",
            native,
            "--directory",
            str(private / "plan"),
        ]
        root_run(*epoch_probe, "--abandon", success=False)
        assert (
            json.loads(root_run("sudo", "-n", "cat", str(private / "plan/epoch-loss-probe.json")))[
                "nativeCommitted"
            ]
            is True
        )
        try:
            result = json.loads(root_run(*command, "--prepare-epochs"))
        except AssertionError:
            # Preserve the wrapper refusal and diagnose only the same retained
            # intent in this owned fixture; any traceback stays in private logs.
            root_run(*epoch_probe, "--resume")
            raise
        assert result["step"] == 9
        epochs = json.loads(root_run(*epoch_probe))
        startup_probe = [
            str(private / "startup-probe.py")
            if value == str(private / "epoch-coordinator.py")
            else value
            for value in epoch_probe
        ]
        epochs["startup_inputs"] = json.loads(root_run(*startup_probe))
        assert epochs["startup_inputs"]["passed"] is True
        publication = [
            str(private / "startup-publication.py")
            if value == str(private / "epoch-coordinator.py")
            else value
            for value in epoch_probe
        ]
        epochs["startup_publication"] = json.loads(root_run(*publication, timeout=330))
        assert epochs["startup_publication"]["passed"] is True
    else:
        epochs = epoch_component(args, private, config, native)
    assert epochs["passed"] is True
    return {
        "epoch_preparation": epochs,
        "history_negative_control": inspected,
        "cases": [
            "actual full backup/restore and disabled preparation",
            "native credentials/history/runtime under fresh identities",
            "exact all-store cleanup and completed validation replay",
            "owner substitution refused; omitted-guard negative control detected",
            "actual process loss with enabled leases resumes exact cleanup",
            "changed KEK input refused and exact original recovered",
        ],
    }


def epoch_component(args, private, config, native):
    return json.loads(
        root_run(
            "sudo",
            "-n",
            sys.executable,
            "-E",
            "-s",
            str(private / "epoch-probe.py"),
            "--package",
            str(args.cutover_package),
            "--server",
            str(args.server_package),
            "--config",
            config,
            "--native",
            native,
            "--directory",
            str(private / "plan"),
        )
    )
