"""Actual current-generation launcher on owned PostgreSQL; no Redis/control supplier."""

from __future__ import annotations

import argparse
import base64
import datetime
import importlib.util
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--root", type=Path, required=True)
p.add_argument("--package", type=Path, required=True)
p.add_argument("--server-package", type=Path, required=True)
p.add_argument("--postgres-bin", type=Path, required=True)
p.add_argument("--atlas-bin", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
p.add_argument("--disabled", action="store_true")
p.add_argument("--management", action="store_true")
a = p.parse_args()
os.umask(0o077)
root = a.root.resolve()
sys.path.insert(0, str(root / "scripts/validation"))
import current_postgres as postgres_ownership  # noqa: E402 - fixed fixture helper.
from current_process import (  # noqa: E402
    cancellation_recorded,
    check_cancellation,
    cleanup_scope,
    install_cancellation,
    run_owned,
    supplier_start_groups,
    unconfirmed_groups,
)

pg = a.postgres_bin.resolve()
a.output.mkdir(mode=0o700, parents=True)
temporary = Path(tempfile.mkdtemp(prefix="aeg-cur-"))
env = {k: v for k, v in os.environ.items() if not k.startswith(("PG", "AEGAEON_", "DATABASE_URL"))}
env["PATH"] = str(pg) + ":" + str(a.atlas_bin.resolve()) + ":" + env["PATH"]
env["AEGAEON_KEY_ENCRYPTION_KEY"] = (
    base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
)
clusters = {}
setup_log = (temporary / "setup.log").open("w")
report = {
    "observed_at": datetime.datetime.now(datetime.UTC).isoformat(),
    "source": str(root),
    "package": str(a.package),
    "server": str(a.server_package),
    "redis_supplier": False,
    "control_supplier": False,
    "distinct_management_credential": a.management,
    "provider_qualification": False,
    "new_composite_discharge": 0,
    "passed": False,
}


def run(  # noqa: C901, PLR0912, PLR0913, PLR0915 — one tracked PostgreSQL ownership boundary
    args,
    *,
    environment=None,
    data=None,
    timeout=180,
    before_wait=None,
    supplier=None,
    private_log=None,
):
    argv = list(map(str, args))
    supplier_cluster = None
    if supplier is not None:
        registered = [c for c in clusters.values() if str(c["data"]) == str(supplier)]
        if (
            len(registered) != 1
            or not argv
            or argv[0] != str(pg / "pg_ctl")
            or argv[-1] != "start"
            or argv.count("-D") != 1
            or argv[argv.index("-D") + 1] != str(supplier)
        ):
            message = "retention is restricted to a tracked PostgreSQL start"
            raise ValueError(message)
        supplier_cluster = registered[0]
        if supplier_cluster.get("postgres_state", "unstarted") not in ("unstarted", "stopped"):
            message = "previous PostgreSQL ownership is still unconfirmed or active"
            raise RuntimeError(message)
        supplier_cluster.update(
            postgres_owner=None,
            postgres_state="starting",
            postgres_generation=supplier_cluster.get("postgres_generation", 0) + 1,
        )
        supplier_cluster.pop("postgres_ownership_error", None)
    if argv and argv[0] == str(pg / "pg_ctl") and argv[-1] == "stop":
        if (
            len(argv) != 9
            or argv[1] != "-D"
            or argv[3:5] != ["-w", "-t"]
            or argv[6] != "-m"
            or argv[7] not in ("fast", "immediate")
            or data is not None
            or before_wait is not None
            or private_log is not None
        ):
            message = "unsupported PostgreSQL stop invocation"
            raise ValueError(message)
        registered = [c for c in clusters.values() if str(c["data"]) == argv[2]]
        if len(registered) != 1:
            message = "PostgreSQL stop requires a registered cluster"
            raise ValueError(message)
        tracked = registered[0]
        check_cancellation()
        try:
            # Signal the verified task through its pidfd, never a PID reread by
            # pg_ctl. Finish bounded confirmation before propagating cancellation.
            with cleanup_scope():
                postgres_ownership.stop(
                    pg,
                    tracked["data"],
                    tracked.get("postgres_owner"),
                    mode=argv[7],
                    timeout=min(timeout, float(argv[5])),
                )
            tracked["postgres_state"] = "stopped"
            tracked.pop("postgres_ownership_error", None)
        except BaseException as failure:
            tracked["postgres_state"] = "unconfirmed"
            tracked["postgres_ownership_error"] = f"{type(failure).__name__}: {failure}"
            raise
        check_cancellation()
        return subprocess.CompletedProcess(args, 0, "", "")
    if argv and argv[0] == str(pg / "pg_ctl") and supplier_cluster is None:
        message = "PostgreSQL control requires a tracked start or verified stop"
        raise ValueError(message)
    result = None
    primary_error = None
    try:
        result = run_owned(
            args,
            root=root,
            env=environment or env,
            data=data,
            timeout=timeout,
            before_wait=before_wait,
            retain_supplier=supplier is not None,
            private_log=private_log,
        )
    except BaseException as failure:
        primary_error = failure
        raise
    finally:
        if supplier_cluster is not None:
            try:
                supplier_cluster["postgres_owner"] = postgres_ownership.capture(pg, supplier)
                supplier_cluster["postgres_state"] = "running"
            except BaseException as failure:
                supplier_cluster["postgres_state"] = "unconfirmed"
                detail = f"PostgreSQL ownership capture failed: {type(failure).__name__}: {failure}"
                supplier_cluster["postgres_ownership_error"] = detail
                if primary_error is not None:
                    primary_error.add_note(detail)
                elif result is None or result.returncode == 0:
                    raise
    if supplier_cluster is not None and result.returncode == 0:
        check_cancellation()
    return result


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
    setup(
        [pg / "pg_ctl", "-D", data, "-l", a.output / (kind + "-postgres.log"), "-w", "start"],
        supplier=data,
    )


def sql(kind, text, database="postgres", *, timeout=180):
    return setup(
        [pg / "psql", "-XqAt", "-v", "ON_ERROR_STOP=1"],
        environment=clusters[kind]["env"] | {"PGDATABASE": database},
        data=text,
        timeout=timeout,
    )


def finish_runtime(primary_error=None):  # noqa: C901, PLR0912, PLR0915 - preserve original errors through teardown/report
    stopped = False
    cleanup_error = None
    with cleanup_scope():
        try:
            if unconfirmed_groups():
                message = "owned work cleanup is unconfirmed; PostgreSQL retained"
                raise RuntimeError(message)  # noqa: TRY301 - record refusal before reporting.
            stopped = True
            for c in clusters.values():
                result = run(
                    [pg / "pg_ctl", "-D", c["data"], "-w", "-t", "20", "-m", "immediate", "stop"],
                    timeout=25,
                )
                stopped = stopped and result.returncode == 0
        except BaseException as failure:  # noqa: BLE001 - retain original error through final reporting.
            cleanup_error = failure
            stopped = False
        finally:
            try:
                setup_log.close()
            except BaseException as failure:  # noqa: BLE001 - retain original error through final reporting.
                cleanup_error = cleanup_error or failure
            report.update(
                owned_suppliers_stopped=stopped,
                owned_work_stopped=not unconfirmed_groups(),
                unconfirmed_groups=unconfirmed_groups(),
                supplier_start_groups=supplier_start_groups(),
                cancellation_recorded=cancellation_recorded(),
            )
            if (
                primary_error is not None
                or cleanup_error is not None
                or not stopped
                or cancellation_recorded()
            ):
                report["passed"] = False
            if primary_error is not None:
                report["work_error"] = type(primary_error).__name__
            if cleanup_error:
                report["cleanup_error"] = type(cleanup_error).__name__
            try:
                if report["passed"]:
                    shutil.rmtree(temporary)
            except BaseException as failure:  # noqa: BLE001 - retain original error through final reporting.
                cleanup_error = cleanup_error or failure
                report.update(passed=False, cleanup_error=type(cleanup_error).__name__)
            if not report["passed"]:
                # Paths only; credential-bearing setup remains private.
                report["recovery"] = {
                    "directory": str(temporary),
                    "cluster_data": [str(c["data"]) for c in clusters.values()],
                    "confirm_work_before_supplier_cleanup": unconfirmed_groups(),
                    "postmasters": [
                        {
                            "data": str(c["data"]),
                            "owner": c.get("postgres_owner"),
                            "state": c.get("postgres_state", "unstarted"),
                            "generation": c.get("postgres_generation", 0),
                            "ownership_error": c.get("postgres_ownership_error"),
                        }
                        for c in clusters.values()
                    ],
                }
            try:
                (a.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
            except BaseException as failure:  # noqa: BLE001 - retain original error through final reporting.
                cleanup_error = cleanup_error or failure
    # Finite completion checkpoint, after report publication and cleanup-scope
    # exit. Signals arriving after this snapshot are outside this boundary.
    cancelled = cancellation_recorded()
    if cancelled and not report["cancellation_recorded"]:
        report.update(passed=False, cancellation_recorded=True)
        try:
            # One rewrite only; further signals cannot restore a success report.
            (a.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        except BaseException as failure:  # noqa: BLE001 - work/cleanup failure keeps priority.
            cleanup_error = cleanup_error or failure
    if cleanup_error is not None:
        if primary_error is None:
            raise cleanup_error
        primary_error.add_note(f"fixture cleanup failed: {type(cleanup_error).__name__}")
    if primary_error is None:
        if not stopped:
            message = "owned supplier cleanup failed"
            raise RuntimeError(message)
        if cancelled:
            check_cancellation()


install_cancellation()
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
    cluster("primary")
    directory = temporary / "fixture"
    directory.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location(
        "fixture", root / "scripts/tests/subject_ownership_fixture.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    os.environ.clear()
    os.environ.update(env)

    def execute(argv, *, data=None, env=None):
        return setup(argv, data=data, environment=env)

    def execute_private(argv, *, data, env, log):
        result = run(argv, data=data, environment=env, timeout=180, private_log=log)
        return result.returncode

    module.ROOT = root
    module.execute = execute
    module.execute_private = execute_private
    c = clusters["primary"]
    admin = f"postgresql://postgres@localhost/postgres?host={c['socket']}&port={c['port']}&sslmode=disable"
    module.prepare_runtime(directory, admin)
    supplier = json.loads((directory / "suppliers.json").read_text())
    parsed = urllib.parse.urlsplit(supplier["urls"]["runtime"])
    database = supplier["names"]["database"]
    primary = f"postgresql://{parsed.username}:{parsed.password}@localhost:{c['port']}/{database}"
    admin_db = urllib.parse.urlsplit(admin)._replace(path="/" + database).geturl()
    if a.management:
        writer = urllib.parse.urlsplit(supplier["urls"]["management"])
        writer_name = supplier["names"]["management"]
        # This production combination uses the documented allowlist, not the
        # broader management grants retained for unrelated legacy test fixtures.
        module.psql(
            admin_db,
            f"REVOKE ALL ON ALL TABLES IN SCHEMA aegaeon FROM {writer_name};",
        )
        setup(
            [
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-v",
                f"runtime_role={writer_name}",
                "-v",
                f"authority_runtime_role={supplier['names']['runtime']}",
                "-v",
                "commit=true",
                "-f",
                root / "scripts/operations/provision-runtime.sql",
            ],
            environment=module.postgres_environment(admin_db),
        )
        module.psql(
            admin_db,
            f"GRANT INSERT,UPDATE ON aegaeon.user_attribute_sources TO {writer_name}; "
            f"GRANT USAGE ON SCHEMA aegaeon_lifecycle TO {writer_name}; "
            f"GRANT SELECT ON aegaeon_lifecycle.current TO {writer_name};",
        )
        env["AEGAEON_MANAGEMENT_DATABASE_URL"] = (
            f"postgresql://{writer.username}:{writer.password}@localhost:{c['port']}/{database}"
            "?sslmode=verify-full"
        )
    fixture = temporary / "fixture.json"
    # The real child needs the ephemeral database credential. Create exclusively
    # with owner-only access, inside the private directory removed in finally.
    descriptor = os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(
            {"primary": primary, "admin": admin_db, "ca": str(temporary / "trusted.crt")}, output
        )
    env.update(
        AEGAEON_DATABASE_URL=primary,
        AEGAEON_TEST_ADMIN_DATABASE_URL=admin,
        AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE=str(fixture),
        AEGAEON_TEST_ORGANIZATION_SERVER=str(a.server_package / "bin/aegaeon-organizations-server"),
        AEGAEON_TEST_ORGANIZATION_PACKAGED_DISABLED=str(int(a.disabled)),
    )
    selector = "organization_packaged_server_requires_configuration_and_drains_signals"
    result = run(
        [
            a.package / "libexec/aegaeon_server",
            selector,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ],
        timeout=240,
    )
    (a.output / "native.log").write_text(result.stdout + result.stderr)
    report.update(selector=selector, returncode=result.returncode)
    report["passed"] = result.returncode == 0 and "1 passed; 0 failed" in result.stdout
    if not report["passed"]:
        message = "current packaged integration failed; private logs retained"
        raise RuntimeError(message)
    if not a.disabled:
        from current_maintenance import exercise

        check_cancellation()
        report["passed"] = False
        report["maintenance"] = exercise(
            temporary, a.server_package, supplier, admin_db, (root, env, run)
        )
        from current_outage import exercise as outage_exercise

        check_cancellation()
        report["outage"] = outage_exercise(
            temporary, a.server_package, admin_db, (clusters["primary"], pg), (root, env, run)
        )
        check_cancellation()
        report["passed"] = True
finally:
    finish_runtime(primary_error=sys.exception())
