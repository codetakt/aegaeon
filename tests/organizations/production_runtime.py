"""Production constructor/delivery test on independent owned TLS stores, no retry."""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
from pathlib import Path

from store_restart import CASES, StoreRestart

p = argparse.ArgumentParser()
p.add_argument("--package", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
case = p.add_mutually_exclusive_group()
case.add_argument("--delivery", action="store_true")
case.add_argument("--background", choices=["normal", "fence"])
case.add_argument("--http", action="store_true")
case.add_argument("--packaged", choices=["enabled", "disabled"])
case.add_argument("--packaged-delivery", action="store_true")
case.add_argument("--packaged-enrollment", action="store_true")
p.add_argument("--protocol", action="store_true")
p.add_argument("--deny-identity-history", action="store_true")
negative_command = p.add_mutually_exclusive_group()
negative_command.add_argument("--deny-dpop-time", action="store_true")
negative_command.add_argument("--deny-code-strlen", action="store_true")
case.add_argument("--control-cli", action="store_true")
case.add_argument("--credential-cli", action="store_true")
case.add_argument("--cutover-cli", action="store_true")
p.add_argument("--cutover-package", type=Path)
p.add_argument("--epoch-coordinator", action="store_true")
p.add_argument(
    "--serving-case",
    choices=["normal", "partial-enable", "after-write", "final-reply-loss", "forward"],
)
case.add_argument("--history-cli", action="store_true")
case.add_argument("--history-restore-cli", action="store_true")
case.add_argument("--snapshot-cli", action="store_true")
case.add_argument("--snapshot-prepare-cli", action="store_true")
case.add_argument("--subject-cli", choices=["normal", "primary-failure"])
case.add_argument("--store-restart", choices=sorted(CASES))
p.add_argument("--server-package", type=Path)
p.add_argument("--deny-token-attribution", action="store_true")
p.add_argument("--root", type=Path, required=True)
p.add_argument("--postgres-bin", type=Path, required=True)
p.add_argument("--redis-bin", type=Path, required=True)
p.add_argument("--atlas-bin", type=Path, required=True)
a = p.parse_args()
a.packaged_delivery = a.packaged_delivery or a.packaged_enrollment
if a.protocol and not a.packaged_enrollment:
    p.error("--protocol requires --packaged-enrollment")
if a.deny_identity_history and (not a.packaged_enrollment or a.protocol):
    p.error("--deny-identity-history requires enrollment without --protocol")
if (a.deny_dpop_time or a.deny_code_strlen) and not a.protocol:
    p.error("denied protocol commands require --protocol")
snapshot_case = a.snapshot_cli or a.snapshot_prepare_cli
history_case = a.history_cli or a.history_restore_cli
if a.deny_token_attribution and a.background != "normal":
    p.error("--deny-token-attribution requires --background normal")
if bool(
    a.packaged
    or a.packaged_delivery
    or a.control_cli
    or a.credential_cli
    or a.cutover_cli
    or history_case
    or snapshot_case
    or a.subject_cli
) != bool(a.server_package):
    p.error("a packaged case and --server-package must be supplied together")
if a.cutover_cli != bool(a.cutover_package):
    p.error("--cutover-cli requires its packaged operator")
if a.epoch_coordinator and not a.cutover_cli:
    p.error("--epoch-coordinator requires --cutover-cli")
if a.serving_case and not a.epoch_coordinator:
    p.error("--serving-case requires --epoch-coordinator")
# Fixture credentials must be private from creation, including before chmod.
os.umask(0o077)
root = a.root.resolve()
pg = a.postgres_bin.resolve()
redis = a.redis_bin.resolve()
atlas = a.atlas_bin.resolve()
a.output.mkdir(mode=0o700)
temporary = Path(tempfile.mkdtemp(prefix="aegaeon-owned-startup-"))
env = {k: v for k, v in os.environ.items() if not k.startswith(("PG", "AEGAEON_", "DATABASE_URL"))}
env["PATH"] = ":".join(map(str, [pg, redis, atlas])) + ":" + env["PATH"]
env["AEGAEON_KEY_ENCRYPTION_KEY"] = (
    base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
)
env["SSL_CERT_FILE"] = str(temporary / "trusted.crt")
# Nix OpenSSL gives its distribution-specific setting precedence when loading
# default trust. Bind both to the same owned fixture CA; never bypass verification.
env["NIX_SSL_CERT_FILE"] = env["SSL_CERT_FILE"]
clusters = {}
token = None
setup_log = (a.output / "setup.log").open("w")
report = {
    "observed_at": datetime.datetime.now(datetime.UTC).isoformat(),
    "package": str(a.package),
    "supplier_qualification": False,
    "new_composite_discharge": 0,
}


def run(args, *, environment=None, data=None, timeout=180, before_wait=None):
    child = subprocess.Popen(  # noqa: S603 — explicit fixed-tool argv, private fixture inputs
        list(map(str, args)),
        cwd=root,
        env=environment or env,
        text=True,
        stdin=subprocess.PIPE if data else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    started = time.monotonic()
    try:
        if before_wait is not None:
            before_wait(child)
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(args, timeout)
        out, err = child.communicate(data, timeout=remaining)
        return subprocess.CompletedProcess(args, child.returncode, out, err)
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)


def setup(args, **kwargs):
    result = run(args, **kwargs)
    setup_log.write(result.stdout + result.stderr)
    setup_log.flush()
    if result.returncode:
        message = "fixture setup failed; private setup.log retained"
        raise RuntimeError(message)
    return result.stdout.strip()


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cluster(kind):
    data = temporary / (kind + "-data")
    sock = temporary / (kind + "-socket")
    sock.mkdir()
    number = port()
    values = dict(
        env, PGHOST=str(sock), PGPORT=str(number), PGDATABASE="postgres", PGUSER="postgres"
    )
    clusters[kind] = {"data": data, "port": number, "socket": sock, "env": values}
    setup(
        [
            pg / "initdb",
            "-D",
            data,
            "-U",
            "postgres",
            "--auth=trust",
            "--no-locale",
            "--encoding=UTF8",
        ]
    )
    (data / "pg_hba.conf").write_text(
        "local all all trust\n"
        "hostssl all all 127.0.0.1/32 scram-sha-256\n"
        "host all all 0.0.0.0/0 reject\n"
    )
    with (data / "postgresql.conf").open("a") as f:
        f.write(
            f"\nlisten_addresses='127.0.0.1'\nport={number}\nunix_socket_directories='{sock}'\nssl=on\nssl_cert_file='{temporary}/server.crt'\nssl_key_file='{temporary}/server.key'\n"
        )
        if a.epoch_coordinator and kind == "control":
            f.write("timezone='Asia/Tokyo'\n")
    setup([pg / "pg_ctl", "-D", data, "-l", a.output / (kind + "-postgres.log"), "-w", "start"])


def sql(kind, text, database="postgres", *, timeout=180):
    return setup(
        [pg / "psql", "-XqAt", "-v", "ON_ERROR_STOP=1"],
        environment=clusters[kind]["env"] | {"PGDATABASE": database},
        data=text,
        timeout=timeout,
    )


try:
    setup(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=owned-startup",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            temporary / "trusted.key",
            "-out",
            temporary / "trusted.crt",
        ]
    )
    setup(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            temporary / "server.key",
            "-out",
            temporary / "server.csr",
        ]
    )
    (temporary / "leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
    )
    setup(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            temporary / "server.csr",
            "-CA",
            temporary / "trusted.crt",
            "-CAkey",
            temporary / "trusted.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            temporary / "leaf.ext",
            "-out",
            temporary / "server.crt",
        ]
    )
    for file in temporary.glob("*.key"):
        file.chmod(0o600)
    if a.packaged_delivery:
        setup(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=delivery.example.test",
                "-keyout",
                temporary / "delivery.key",
                "-out",
                temporary / "delivery.csr",
            ]
        )
        (temporary / "delivery.ext").write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:delivery.example.test,DNS:private.example.test\n"
        )
        setup(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                temporary / "delivery.csr",
                "-CA",
                temporary / "trusted.crt",
                "-CAkey",
                temporary / "trusted.key",
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                temporary / "delivery.ext",
                "-out",
                temporary / "delivery.crt",
            ]
        )
        (temporary / "delivery.key").chmod(0o600)
    cluster("primary")
    cluster("control")
    for version in range(1, 17):
        setup(
            [
                pg / "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                root / f"db/organization-witness/schema-v{version}.sql",
            ],
            environment=clusters["control"]["env"],
        )
    passwords = {role: secrets.token_urlsafe(32) for role in ["runtime", "maintenance"]}
    for role, password in passwords.items():
        sql(
            "control",
            f"CREATE ROLE witness_{role} LOGIN PASSWORD '{password}' "
            f"IN ROLE aegaeon_organization_witness_{role};",
        )
    sql("control", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO witness_runtime")
    directory = temporary / "primary-fixture"
    directory.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location(
        "fixture", root / "scripts/tests/subject_ownership_fixture.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The existing fixture's two subprocess entrypoints use the same private env.
    os.environ.clear()
    os.environ.update(env)

    def execute(argv, *, data=None, env=None):
        setup(argv, data=data, environment=env)

    module.ROOT = root
    module.execute = execute
    c = clusters["primary"]
    admin = f"postgresql://postgres@localhost/postgres?host={c['socket']}&port={c['port']}&sslmode=disable"
    module.prepare_runtime(directory, admin)
    supplier = json.loads((directory / "suppliers.json").read_text())
    parsed = urllib.parse.urlsplit(supplier["urls"]["runtime"])
    database = supplier["names"]["database"]
    login = supplier["names"]["runtime"]
    sql("primary", f"GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {login}", database)
    primary_url = (
        f"postgresql://{parsed.username}:{parsed.password}@localhost:{c['port']}/{database}"
    )
    maintenance = urllib.parse.urlsplit(supplier["urls"]["maintenance"])
    maintenance_login = supplier["names"]["maintenance"]
    sql(
        "primary",
        f"GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {maintenance_login}",
        database,
    )
    primary_maintenance_url = f"postgresql://{maintenance.username}:{maintenance.password}@localhost:{c['port']}/{database}"
    number = port()
    password = secrets.token_urlsafe(32)
    # Exercise the exact shipped worker command ceiling, not expanding Redis
    # categories (which omit TIME and transaction commands).
    sys.path.insert(0, str(root / "tests/organizations/legacy_operations"))
    from organization_recovery_redis import WORKER_COMMANDS

    commands = set(WORKER_COMMANDS)
    selectors = []
    if a.deny_dpop_time:
        commands.remove("time")
    if a.deny_code_strlen:
        commands.remove("strlen")
        # Continuity now also uses STRLEN. Permit only its exact marker so this
        # negative control still reaches authorization-code publication. Code
        # keys retain the denied command; production worker ACLs are unchanged.
        selectors.append("(+strlen ~aegaeon:organization-store-continuity:v1)")
    if a.deny_token_attribution:
        commands.remove("client|setname")
    report["redis_worker_commands"] = sorted(commands)
    report["redis_worker_selectors"] = selectors
    redis_config = temporary / "redis.conf"
    redis_config.write_text(
        f"bind 127.0.0.1\n"
        f"port 0\n"
        f"tls-port {number}\n"
        f"tls-cert-file {temporary}/server.crt\n"
        f"tls-key-file {temporary}/server.key\n"
        f"tls-ca-cert-file {temporary}/trusted.crt\n"
        f"tls-auth-clients no\n"
        f"dir {temporary}\n"
        f"appendonly yes\n"
        f"appendfsync always\n"
        f'save ""\n'
        f"user default off\n"
        f"user runtime on >{password} ~* -@all "
        + " ".join("+" + command for command in sorted(commands))
        + " "
        + " ".join(selectors)
        + "\n"
    )
    if a.cutover_cli:
        from cutover_journey import configure_retired_token

        configure_retired_token(root, temporary, redis_config, password)
    redis_config.chmod(0o600)
    token = subprocess.Popen(  # noqa: S603 — explicit fixed-tool argv, private fixture inputs
        [str(redis / "redis-server"), str(redis_config)],
        env=env,
        stdout=setup_log,
        stderr=setup_log,
        start_new_session=True,
    )
    deadline = time.monotonic() + 10
    while True:
        if token.poll() is not None:
            message = "owned Redis exited"
            raise RuntimeError(message)
        try:
            with socket.create_connection(("127.0.0.1", number), timeout=0.1):
                break
        except OSError:
            if time.monotonic() > deadline:
                message = "owned Redis startup exceeded deadline"
                raise RuntimeError(message) from None
            time.sleep(0.02)
    token_url = f"rediss://runtime:{password}@localhost:{number}/3"
    config = {
        "primary": primary_url,
        "primary_maintenance": primary_maintenance_url,
        "token": token_url,
        "ca": str(temporary / "trusted.crt"),
    }
    for key, role in [("control", "runtime"), ("maintenance", "maintenance")]:
        config[key] = (
            f"postgresql://witness_{role}:{passwords[role]}@localhost:{clusters['control']['port']}/postgres"
        )
    path = temporary / "fixture.json"
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    env.update(
        AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE=str(path), AEGAEON_DATABASE_URL=primary_url
    )
    for key in set(
        re.findall(
            r'"(AEGAEON_[A-Z0-9_]+_REDIS_URL)"',
            (
                root / "crates/server/src/config/runtime_boundary/shared_store/inventory.rs"
            ).read_text(),
        )
    ):
        env[key] = token_url
    if a.epoch_coordinator:
        env["AEGAEON_TEST_ORGANIZATION_CUTOVER_MULTIPLE"] = "1"
    if snapshot_case:
        env["AEGAEON_TEST_ORGANIZATION_SNAPSHOT_FIXTURE"] = "1"
    if a.packaged_enrollment:
        if a.deny_dpop_time:
            env["AEGAEON_TEST_DENY_DPOP_TIME"] = "1"
        if a.deny_code_strlen:
            env["AEGAEON_TEST_DENY_CODE_STRLEN"] = "1"
        report["initial_identity_counts"] = json.loads(
            sql(
                "primary",
                "SELECT jsonb_build_array("
                "(SELECT count(*) FROM aegaeon.end_users),"
                "(SELECT count(*) FROM aegaeon.end_user_identity_owners),"
                "(SELECT count(*) FROM aegaeon.end_user_subject_reservations))",
                database,
            )
        )
        if report["initial_identity_counts"] != [0, 0, 0]:
            message = "owned enrollment fixture must have empty identity history"
            raise RuntimeError(message)
        if not a.deny_identity_history:
            env["AEGAEON_TEST_ORGANIZATION_ENROLLMENT_FIXTURE"] = "1"
    binary = a.package / "libexec/aegaeon_server"
    if (
        a.control_cli
        or a.credential_cli
        or a.cutover_cli
        or history_case
        or snapshot_case
        or a.subject_cli
    ):
        selector = "organization_packaged_delivery_prepare"
        report["server_package"] = str(a.server_package)
    elif a.packaged_delivery:
        selector = "organization_packaged_delivery_prepare"
        report["server_package"] = str(a.server_package)
        report["network"] = (
            "isolated user/network/mount namespace, no external routes; production DNS/TLS"
        )
    elif a.packaged:
        selector = "organization_packaged_server_requires_configuration_and_drains_signals"
        executable = a.server_package / "bin/aegaeon-organizations-server"
        env["AEGAEON_TEST_ORGANIZATION_SERVER"] = str(executable)
        env["AEGAEON_TEST_ORGANIZATION_PACKAGED_DISABLED"] = str(int(a.packaged == "disabled"))
        report["server_package"] = str(a.server_package)
        report["launcher_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
        report["database_policy"] = a.packaged
    elif a.store_restart:
        selector = "organization_production_store_restart_acceptance"
    elif a.http:
        selector = "organization_production_http_management_and_child_fences"
    elif a.background:
        selector = (
            "organization_production_background_initial_work_and_shutdown"
            if a.background == "normal"
            else "organization_production_background_parent_fence_stops_checks"
        )
    else:
        selector = (
            "organization_production_delivery_from_enabled_policy_sends_once_and_fences"
            if a.delivery
            else "organization_production_startup_uses_parent_child_and_releases_actual_stores"
        )
    report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    report["selector"] = selector
    before_wait = None
    restart = None
    if snapshot_case:
        from snapshot_journey import capture_dependencies

        def before_wait(child):
            capture_dependencies(temporary, sql, database, child)

    elif a.store_restart:
        restart = StoreRestart(
            case=a.store_restart,
            directory=temporary / "store-restart",
            temporary=temporary,
            binary=binary,
            environment=env,
            run=run,
            sql=sql,
            setup=setup,
            clusters=clusters,
            postgres_bin=pg,
            redis_bin=redis,
            redis_config=redis_config,
            token=token,
            setup_log=setup_log,
            database=database,
            output=a.output,
        )
        before_wait = restart.drive
    try:
        result = run(
            [binary, selector, "--ignored", "--nocapture", "--test-threads=1"],
            timeout=600 if a.store_restart else 120,
            before_wait=before_wait,
        )
    finally:
        if restart is not None:
            # A refused barrier can follow a successful Redis process replacement.
            # Cleanup must own that newest process even when run raises.
            token = restart.token
            report["store_restart"] = restart.report
    (a.output / "test.stdout").write_text(result.stdout)
    (a.output / "test.stderr").write_text(result.stderr)
    report["returncode"] = result.returncode
    report["runtime_test_succeeded"] = result.returncode == 0 and "1 passed" in result.stdout
    if a.cutover_cli and report["runtime_test_succeeded"]:
        from cutover_journey import journey as cutover_journey

        try:
            cutover_journey(temporary, a, (root, env, run, sql, setup, cluster, clusters), report)
        except Exception as error:  # noqa: BLE001 — retain result and clean owned suppliers
            report["cutover_failure"] = type(error).__name__
            # Child stderr can contain fixture-only endpoints or SQL literals.
            # Keep it private and outside the public result/artifact inventory.
            failure = a.output / "cutover-private-failure.txt"
            with os.fdopen(os.open(failure, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                f.write(str(error))
            report["cutover_stack"] = [
                (Path(frame.filename).name, frame.lineno, frame.name)
                for frame in traceback.extract_tb(error.__traceback__)
            ]
            if getattr(error, "verify_message", None):
                report["cutover_tls_reason"] = error.verify_message
            if isinstance(error, RuntimeError):
                report["cutover_reason"] = str(error)
    if a.credential_cli and report["runtime_test_succeeded"]:
        from credential_journey import journey as credential_journey

        try:
            credential_journey(temporary, a.server_package, env, run, report)
        except Exception as error:  # noqa: BLE001 — retain result and clean owned suppliers
            report["credential_failure"] = type(error).__name__
            if isinstance(error, RuntimeError):
                report["credential_reason"] = str(error)
    if a.control_cli and report["runtime_test_succeeded"]:
        from control_journey import journey as control_journey

        try:
            control_journey(temporary, a.server_package, env, run, report)
        except Exception as error:  # noqa: BLE001 — retain state and clean all owned suppliers
            report["control_failure"] = type(error).__name__
            if isinstance(error, RuntimeError):
                report["control_reason"] = str(error)
    if history_case and report["runtime_test_succeeded"]:
        from history_journey import journey as history_journey

        try:
            history_journey(
                temporary,
                a.server_package,
                (root, env, run, sql),
                report,
                restoring=a.history_restore_cli,
            )
        except Exception as error:  # noqa: BLE001 — retain state and clean owned suppliers
            report["history_failure"] = type(error).__name__
            if isinstance(error, RuntimeError):
                report["history_reason"] = str(error)
    if a.subject_cli and report["runtime_test_succeeded"]:
        from subject_journey import journey as subject_journey

        try:
            subject_journey(
                temporary, a.server_package, (root, env, run, sql), report, a.subject_cli
            )
        except Exception as error:  # noqa: BLE001 — retain state and clean owned suppliers
            report["subject_failure"] = type(error).__name__
            if isinstance(error, RuntimeError):
                report["subject_reason"] = str(error)
    if snapshot_case and report["runtime_test_succeeded"]:
        from snapshot_journey import journey as snapshot_journey

        try:
            snapshot_journey(
                temporary,
                a.server_package,
                (root, env, run, sql),
                report,
                preparing=a.snapshot_prepare_cli,
            )
        except Exception as error:  # noqa: BLE001 — retain state and clean owned suppliers
            report["snapshot_failure"] = type(error).__name__
            if isinstance(error, RuntimeError):
                report["snapshot_reason"] = str(error)
    if a.packaged_delivery and report["runtime_test_succeeded"]:
        from delivery_journey import journey

        def observe_work(label):
            counts = json.loads(
                sql(
                    "control",
                    "SELECT jsonb_build_array("
                    "(SELECT COALESCE(sum(generation),0) "
                    "FROM organization_witness.deployment_slots),"
                    "(SELECT COALESCE(sum(generation),0) FROM organization_witness.slots))",
                )
            )
            report.setdefault("generation_trace", []).append({"stage": label, "counts": counts})
            if label in {"password-recovered", "member-registered"}:
                cutoff = int(
                    sql(
                        "primary",
                        "SELECT max(organization_reauthentication_after) FROM aegaeon.end_users",
                        database,
                    )
                )
                report.setdefault("identity_login_cutoffs", {})[label] = cutoff
                if label == "password-recovered":
                    report["reauthentication_cutoff_before_login"] = cutoff
                return cutoff
            return None

        try:
            journey(
                temporary,
                a.server_package,
                env,
                run,
                report,
                enrollment=a.packaged_enrollment,
                protocol=a.protocol,
                observe=observe_work if a.packaged_enrollment else None,
            )
        except Exception as error:  # noqa: BLE001 — record failure, collect state, then fail below
            # Still capture durable control rows before stopping/removing the
            # owned suppliers. Do not turn a failed journey into a successful setup.
            report["journey_failure"] = type(error).__name__
            if isinstance(error, RuntimeError):
                report["journey_reason"] = str(error)
    if a.packaged or a.packaged_delivery:
        process_logs = [log.read_text() for log in temporary.glob("*.log")]
        secrets_to_check = [
            *passwords.values(),
            password,
            urllib.parse.unquote(parsed.password),
            env["AEGAEON_KEY_ENCRYPTION_KEY"],
        ]
        report["process_logs_secret_free"] = not any(
            secret in log for secret in secrets_to_check for log in process_logs
        )
    # Preserve diagnostic SQL state without credentials after either outcome.
    if a.packaged_enrollment:
        report["final_identity_counts"] = json.loads(
            sql(
                "primary",
                "SELECT jsonb_build_array("
                "(SELECT count(*) FROM aegaeon.end_users),"
                "(SELECT count(*) FROM aegaeon.end_user_identity_owners),"
                "(SELECT count(*) FROM aegaeon.end_user_subject_reservations),"
                "(SELECT count(*) FROM aegaeon.organization_memberships))",
                database,
            )
        )
        report["final_identity_authority"] = json.loads(
            sql(
                "primary",
                "SELECT COALESCE(jsonb_agg(jsonb_build_object("
                "'revision',organization_identity_revision,"
                "'reauthentication_after',organization_reauthentication_after)), '[]'::jsonb) "
                "FROM aegaeon.end_users",
                database,
            )
        )
        expected_identity = (
            [0, 0, 0, 0]
            if a.deny_identity_history
            else [2, 2, 2, 3]
            if a.protocol and not (a.deny_dpop_time or a.deny_code_strlen)
            else [1, 1, 1, int(a.protocol and not a.deny_dpop_time)]
        )
        report["identity_counts_match"] = report["final_identity_counts"] == expected_identity
        if not report["identity_counts_match"]:
            report.setdefault("journey_failure", "unexpected identity or membership creation")
        report["history_namespaces"] = json.loads(
            sql(
                "control",
                "SELECT COALESCE(jsonb_agg(jsonb_build_object("
                "'environment',environment_id,'sealed',sealed,'owners',owner_count,"
                "'subjects',subject_count)),'[]'::jsonb) "
                "FROM organization_witness.history_namespaces",
            )
        )
    report["parent"] = json.loads(
        sql(
            "control",
            "SELECT COALESCE(jsonb_agg(to_jsonb(d)),'[]'::jsonb) "
            "FROM organization_witness.deployments d",
        )
    )
    report["child"] = json.loads(
        sql(
            "control",
            "SELECT COALESCE(jsonb_agg(to_jsonb(d)),'[]'::jsonb) "
            "FROM organization_witness.authorities d",
        )
    )
    report["parent_slots"] = json.loads(
        sql(
            "control",
            "SELECT COALESCE(jsonb_agg(to_jsonb(s)),'[]'::jsonb) "
            "FROM organization_witness.deployment_slots s WHERE generation>0",
        )
    )
    report["child_slots"] = json.loads(
        sql(
            "control",
            "SELECT COALESCE(jsonb_agg(to_jsonb(s)),'[]'::jsonb) "
            "FROM organization_witness.slots s WHERE generation>0",
        )
    )
    counts = [
        sum(slot["generation"] for slot in report[key]) for key in ("parent_slots", "child_slots")
    ]
    clean = not any(
        slot["pending"] for key in ("parent_slots", "child_slots") for slot in report[key]
    )
    expected = (
        [14, 10]
        if a.packaged
        else (
            [16, 6] if a.http else ([4, 4] if a.background else ([8, 8] if a.delivery else [2, 2]))
        )
    )
    if a.packaged_delivery:
        expected = report.get("journey", {}).get("expected_generations")
    if a.control_cli:
        expected = report.get("control_journey", {}).get("expected_generations")
    if history_case or snapshot_case or a.subject_cli or a.credential_cli or a.cutover_cli:
        expected = [0, 0]
    if a.store_restart:
        expected = (
            [2, 2]
            if a.store_restart.startswith("pending-")
            else ([4, 4] if a.store_restart.endswith("-rollback") else [5, 5])
        )
    report["observed_generations"] = counts
    report["expected_generations"] = expected
    report["all_expected_work_owned"] = counts == expected and clean
    if a.store_restart:
        pending = [
            sum(slot["pending"] for slot in report[key]) for key in ("parent_slots", "child_slots")
        ]
        expected_pending = [1, 1] if a.store_restart.startswith("pending-") else [0, 0]
        report["observed_pending"] = pending
        report["expected_pending"] = expected_pending
        report["all_expected_work_owned"] = counts == expected and pending == expected_pending
    if a.packaged_delivery and expected is not None:
        # /health is store-free. Initial construction/three background passes,
        # each actual API request and each one-shot CLI give a lower bound.
        # LISTEN wakeups from configuration/identity writes additionally dispatch
        # paired owners; their asynchronous count is not a fixed HTTP inventory.
        extra = [count - minimum for count, minimum in zip(counts, expected, strict=True)]
        report["additional_owned_checks"] = extra
        report["expected_generations_semantics"] = "HTTP/CLI and initial background lower bound"
        report["all_expected_work_owned"] = clean and extra[0] == extra[1] and extra[0] >= 0
    if a.serving_case:
        from cutover_serving_probe import ownership as serving_ownership

        # Live background work has variable generations. Check an independently
        # observed HTTP lower bound and the exact deliberately abandoned owner.
        report["expected_generations"], report["all_expected_work_owned"] = serving_ownership(
            report, a.serving_case, counts
        )
    if a.deny_token_attribution:
        # Exercise the same real startup with exactly the required attribution
        # command removed. Failure must preserve durable uncertainty; it cannot
        # fall back to an unowned background pass or report readiness.
        report["expected_refusal"] = "missing CLIENT SETNAME permission"
        report["passed"] = (
            result.returncode == 101
            and "initial cleanup work failed" in result.stderr
            and 2 <= counts[1] <= counts[0] <= 4
            and all(
                any(slot["pending"] for slot in report[key])
                for key in ("parent_slots", "child_slots")
            )
        )
    else:
        report["passed"] = report["runtime_test_succeeded"] and report["all_expected_work_owned"]
        if a.packaged or a.packaged_delivery:
            report["passed"] = report["passed"] and report["process_logs_secret_free"]
        if a.packaged_delivery:
            report["passed"] = report["passed"] and report.get("journey", {}).get("passed", False)
        if a.packaged_enrollment:
            report["passed"] = report["passed"] and report["identity_counts_match"]
        if snapshot_case:
            report["passed"] = report["passed"] and report.get("snapshot_journey", {}).get(
                "passed", False
            )
        if a.control_cli:
            report["passed"] = report["passed"] and report.get("control_journey", {}).get(
                "passed", False
            )
    if history_case:
        report["passed"] = report["passed"] and report.get("history_journey", {}).get(
            "passed", False
        )
    if a.subject_cli:
        report["passed"] = report["passed"] and report.get("subject_journey", {}).get(
            "passed", False
        )
    if a.cutover_cli:
        report["passed"] = report["passed"] and report.get("cutover_journey", {}).get(
            "passed", False
        )
    if a.credential_cli:
        report["passed"] = report["passed"] and report.get("credential_journey", {}).get(
            "passed", False
        )
    if a.store_restart:
        report["passed"] = report["passed"] and report.get("store_restart", {}).get(
            "completed", False
        )
    if history_case or snapshot_case:
        report["maintenance_keeps_authority_fenced"] = all(
            report[key] and all(authority["phase"] == "fenced" for authority in report[key])
            for key in ("parent", "child")
        )
        report["passed"] = report["passed"] and report["maintenance_keeps_authority_fenced"]
    if not report["passed"]:
        message = "production startup test failed; private outputs retained"
        raise RuntimeError(message)
finally:
    cleanup_errors = []
    if a.packaged or a.packaged_delivery:
        # Private process diagnostics survive failure; credentials/data do not.
        # The Nix check exports only result.json, never these private captures.
        for log in temporary.glob("*.log"):
            try:
                shutil.copyfile(log, a.output / f"packaged-{log.name}")
            except OSError:
                cleanup_errors.append("process diagnostic capture")
    if token is not None and token.poll() is None:
        try:
            token.terminate()
            try:
                token.wait(timeout=10)
            except subprocess.TimeoutExpired:
                token.kill()
                token.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("token")
    for name, item in clusters.items():
        if (item["data"] / "postmaster.pid").exists():
            try:
                setup([pg / "pg_ctl", "-D", item["data"], "-m", "fast", "-w", "stop"])
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                # Attempt every owned supplier even when one stop fails.
                cleanup_errors.append(name)
    if not cleanup_errors:
        shutil.rmtree(temporary)
    report["cleanup_errors"] = cleanup_errors
    report["owned_suppliers_removed"] = not temporary.exists()
    if cleanup_errors:
        report["passed"] = False
    (a.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    setup_log.close()
    if cleanup_errors:
        message = "owned supplier cleanup incomplete; private fixture retained"
        raise RuntimeError(message)
print(
    json.dumps(
        {"passed": report["passed"], "owned_suppliers_removed": report["owned_suppliers_removed"]}
    )
)
