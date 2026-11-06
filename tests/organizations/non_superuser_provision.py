"""Local PostgreSQL creator grants; this does not qualify an RDS deployment."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path

import psycopg
from psycopg import sql


def refused(connection, statement, expected):
    """Each injected grant rolls back, including when the asserted refusal fails."""
    try:
        with connection.transaction():
            connection.execute(statement)
            message = "injected privilege was accepted"
            raise AssertionError(message)
    except psycopg.Error as error:
        if error.sqlstate not in ("42501", "P0001") or error.diag.message_primary != expected:
            raise

        return error.diag.message_primary


def verify_roles(database_url, names):
    runtime = sql.Literal(names["runtime"])
    maintenance = sql.Literal(names["maintenance"])
    failures = {}
    with psycopg.connect(database_url, autocommit=True) as db:
        preflight = sql.SQL("SELECT aegaeon.subject_history_preflight({})").format(runtime)
        db.execute(preflight)
        # No elevated rights were assigned to either application identity.
        for kind in ("runtime", "maintenance"):
            assert db.execute(
                "SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication "
                "OR rolbypassrls) FROM pg_roles WHERE rolname=%s",
                (names[kind],),
            ).fetchone() == (True,)
        for kind, group in (
            ("runtime", "aegaeon_subject_owner"),
            ("runtime", "aegaeon_subject_maintenance"),
            ("maintenance", "aegaeon_subject_owner"),
        ):
            check = (
                preflight
                if kind == "runtime"
                else sql.SQL("SELECT aegaeon.subject_history_check_maintenance_role({})").format(
                    maintenance
                )
            )
            statement = sql.SQL(
                "GRANT {} TO {} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; {}"
            ).format(sql.Identifier(group), sql.Identifier(names[kind]), check)
            failures[kind + "_admin_" + group] = refused(
                db,
                statement,
                (
                    "subject runtime has protected group membership, "
                    "including administrative authority"
                    if kind == "runtime"
                    else "maintenance actor has ownership membership, "
                    "including administrative authority"
                ),
            )
        failures["ordinary_privileged_maintenance"] = refused(
            db,
            sql.SQL(
                "CREATE ROLE unsafe_maintenance CREATEROLE; "
                "GRANT aegaeon_subject_maintenance TO unsafe_maintenance; {}"
            ).format(preflight),
            "maintenance actor can bypass protected authority",
        )
        failures["missing_owner_admin"] = refused(
            db,
            sql.SQL(
                "REVOKE ADMIN OPTION FOR aegaeon_subject_owner FROM fixture_dba "
                "GRANTED BY postgres CASCADE; {}"
            ).format(preflight),
            "maintenance actor has ownership membership, including administrative authority",
        )
        failures["group_parent"] = refused(
            db,
            sql.SQL(
                "CREATE ROLE unsafe_parent; GRANT unsafe_parent TO aegaeon_subject_maintenance; {}"
            ).format(preflight),
            "subject authority role shape is incompatible",
        )
        # ADMIN grants by a non-superuser do not confer this exception.
        failures["nonbootstrap_administrator"] = refused(
            db,
            sql.SQL(
                "CREATE ROLE forged_admin CREATEROLE; SET LOCAL ROLE fixture_dba; "
                "GRANT aegaeon_subject_owner, aegaeon_subject_maintenance TO forged_admin "
                "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; RESET ROLE; {}"
            ).format(preflight),
            "maintenance actor has ownership membership, including administrative authority",
        )
        db.execute(preflight)
    return failures


def prepare_and_verify(root, fixture, log, url):
    actor_url = url.replace("postgres@", "fixture_dba@")
    directory = root / "fixture"
    directory.mkdir(mode=0o700)
    # Capture subprocess output in the private temporary directory.
    original_execute = fixture.execute

    def execute(argv, *, data=None, env=None):
        subprocess.run(  # noqa: S603 - actual repository fixture commands
            argv,
            cwd=fixture.ROOT,
            input=data,
            text=True,
            env=env,
            check=True,
            stdout=log,
            stderr=log,
        )

    fixture.execute = execute
    fixture.prepare_runtime(directory, actor_url)
    fixture.execute = original_execute
    names = json.loads((directory / "owned-resources.json").read_text())
    database_url = url.replace("/postgres?", "/" + names["database"] + "?")
    failures = verify_roles(database_url, names)
    # Re-running the actual installer still rejects an unrelated member.
    with psycopg.connect(database_url, autocommit=True) as db:
        db.execute("CREATE ROLE unknown_member")
        db.execute("GRANT aegaeon_subject_owner TO unknown_member")
    result = subprocess.run(  # noqa: S603 - fixed psql and generated identifiers
        [  # noqa: S607 - pinned supplier tool
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-v",
            f"runtime_role={names['runtime']}",
            "-v",
            f"migration_role={names['migration']}",
            "-v",
            f"maintenance_role={names['maintenance']}",
            "-f",
            str(fixture.ROOT / "scripts/operations/provision-subject-ownership.sql"),
        ],
        env=fixture.postgres_environment(
            actor_url.replace("/postgres?", "/" + names["database"] + "?")
        ),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0, result.stderr
    assert "unexpected member" in result.stderr, result.stderr
    failures["unrelated_owner_member"] = "installer refused"
    return failures


def prepare_source(args, root):
    source = root / "source"
    (source / "scripts/operations").mkdir(parents=True)
    (source / "db").mkdir()
    (source / "db/migrations").symlink_to(args.migrations)
    (source / "atlas.hcl").symlink_to(args.atlas_config)
    for name, path in (
        ("provision-subject-ownership.sql", args.provision),
        ("provision-organizations.sql", args.runtime_provision),
        ("provision-runtime.sql", args.ordinary_provision),
    ):
        (source / "scripts/operations" / name).symlink_to(path)
    spec = importlib.util.spec_from_file_location("subject_fixture", args.fixture)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    fixture.ROOT = source
    return fixture


def run_case(args, setting):
    with tempfile.TemporaryDirectory(prefix="aegaeon-nonsuper-") as temporary:
        root = Path(temporary)
        socket = root / "socket"
        socket.mkdir()
        data = root / "data"
        fixture = prepare_source(args, root)
        log = (root / "commands.log").open("w")

        def command(*arguments):
            subprocess.run(  # noqa: S603 - fixed pinned tools and owned paths
                arguments,
                check=True,
                stdout=log,
                stderr=log,
                timeout=60,
            )

        command(
            "initdb",
            "-D",
            str(data),
            "--no-locale",
            "--encoding=UTF8",
            "-A",
            "trust",
            "-U",
            "postgres",
        )
        with (data / "postgresql.conf").open("a") as config:
            config.write(
                f"\nlisten_addresses=''\nunix_socket_directories='{socket}'\n"
                f"port=55479\ncreaterole_self_grant='{setting}'\n"
            )
        command("pg_ctl", "-D", str(data), "-l", str(root / "postgres.log"), "-w", "start")
        try:
            url = (
                f"postgresql://postgres@localhost/postgres?host={socket}&port=55479&sslmode=disable"
            )
            with psycopg.connect(url, autocommit=True) as bootstrap:
                bootstrap.execute("CREATE ROLE fixture_dba LOGIN NOSUPERUSER CREATEDB CREATEROLE")
                version = bootstrap.execute("SHOW server_version").fetchone()[0]
            failures = prepare_and_verify(root, fixture, log, url)
            return {
                "postgresql": version,
                "createrole_self_grant": setting,
                "prepared": True,
                "refusals": failures,
                "actual_rds": False,
                "owned_supplier_stopped": True,
            }
        finally:
            command("pg_ctl", "-D", str(data), "-m", "fast", "-w", "stop")
            log.close()


def main():
    parser = argparse.ArgumentParser()
    for name in (
        "fixture",
        "migrations",
        "provision",
        "runtime-provision",
        "ordinary-provision",
        "atlas-config",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    records = [run_case(args, setting) for setting in ("", "set,inherit")]
    args.output.write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
