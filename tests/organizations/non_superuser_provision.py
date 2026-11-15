"""Local PostgreSQL creator grants; this does not qualify an RDS deployment."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

import psycopg
from management_role_authority import (
    verify_management_role_authority,
    verify_pre_migration_authority,
)
from psycopg import sql
from psycopg.types.json import Jsonb


def management_provision(fixture, names, url):
    return subprocess.run(  # noqa: S603 - pinned psql and private fixture identities.
        [  # noqa: S607 - psql is supplied by the pinned PostgreSQL fixture PATH.
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-v",
            "commit=true",
            "-v",
            f"serving_role={names['management']}",
            "-v",
            f"migration_role={names['migration']}",
            "-v",
            f"bootstrap_role={names['bootstrap']}",
            "-f",
            str(fixture.ROOT / "scripts/operations/provision-management-authority.sql"),
        ],
        env=fixture.postgres_environment(url),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def membership_rows(db):
    return db.execute(
        "SELECT roleid,member,grantor,admin_option,inherit_option,set_option "
        "FROM pg_auth_members ORDER BY roleid,member,grantor"
    ).fetchall()


def verify_new_management_memberships(fixture, url):
    names = {kind: "new_management_" + kind for kind in ("management", "migration", "bootstrap")}
    failures = {}
    with psycopg.connect(url, autocommit=True) as db:
        for name in [*names.values(), "new_management_unrelated"]:
            db.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(name)))
        db.execute("CREATE ROLE new_management_nested NOLOGIN")
        db.execute("GRANT new_management_nested TO new_management_unrelated")
        for kind in ("migration", "bootstrap"):
            for child in ("new_management_unrelated", "new_management_nested"):
                before = membership_rows(db)
                db.execute(
                    sql.SQL("GRANT {} TO {}").format(
                        sql.Identifier(names[kind]), sql.Identifier(child)
                    )
                )
                injected = membership_rows(db)
                try:
                    result = management_provision(
                        fixture, names, url.replace("postgres@", "fixture_dba@")
                    )
                    assert result.returncode != 0, (
                        kind,
                        child,
                        "new provisioning accepted an indirect member",
                    )
                    assert "unexpected member" in result.stderr, result.stderr
                    assert membership_rows(db) == injected
                    assert db.execute(
                        "SELECT count(*) FROM pg_roles WHERE rolname IN "
                        "('aegaeon_management_authority_owner','aegaeon_management_bootstrap')"
                    ).fetchone() == (0,)
                    failures["new_" + kind + "_" + child] = "rejected before first authority grant"
                finally:
                    db.execute(
                        sql.SQL("REVOKE {} FROM {} GRANTED BY postgres CASCADE").format(
                            sql.Identifier(names[kind]), sql.Identifier(child)
                        )
                    )
                assert membership_rows(db) == before
        failures.update(
            verify_pre_migration_authority(
                db, fixture, names, url.replace("postgres@", "fixture_dba@"), management_provision
            )
        )
        for name in [*names.values(), "new_management_unrelated", "new_management_nested"]:
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))
    return failures


def membership_cases(names):
    for group, approved in (
        ("aegaeon_management_authority_owner", names["migration"]),
        ("aegaeon_management_bootstrap", names["bootstrap"]),
    ):
        for suffix, options in (
            ("inherit", "INHERIT TRUE, SET FALSE"),
            ("set", "INHERIT FALSE, SET TRUE"),
            ("admin_only", "ADMIN TRUE, INHERIT FALSE, SET FALSE"),
        ):
            yield group + "_" + suffix, [(group, "management_unrelated", options, "postgres")]
        yield (
            group + "_nested",
            [
                (
                    "management_unrelated_group",
                    "management_unrelated",
                    "INHERIT TRUE, SET TRUE",
                    "postgres",
                ),
                (group, "management_unrelated_group", "INHERIT TRUE, SET TRUE", "postgres"),
            ],
        )
        yield (
            group + "_approved_login_nested",
            [
                (approved, "management_unrelated", "INHERIT FALSE, SET TRUE", "postgres"),
            ],
        )
        for parent in ("management_unrelated", "management_unrelated_group"):
            yield (
                group + "_parent_" + parent,
                [(parent, group, "INHERIT FALSE, SET FALSE", "postgres")],
            )
    yield (
        "protected_group_bridge",
        [
            (
                "aegaeon_management_authority_owner",
                "aegaeon_management_bootstrap",
                "INHERIT FALSE, SET FALSE",
                "postgres",
            ),
        ],
    )
    yield (
        "non_superuser_dual_admin",
        [
            (group, "management_unrelated", "ADMIN TRUE, INHERIT FALSE, SET FALSE", "fixture_dba")
            for group in ("aegaeon_management_authority_owner", "aegaeon_management_bootstrap")
        ],
    )


def check_management_case(db, fixture, names, urls, injection):
    actor_url, migrated_url = urls
    case, grants = injection
    before = membership_rows(db)
    try:
        for group, member, options, grantor in grants:
            db.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(grantor)))
            db.execute(
                sql.SQL("GRANT {} TO {} WITH " + options).format(
                    sql.Identifier(group), sql.Identifier(member)
                )
            )
            db.execute("RESET ROLE")
        injected = membership_rows(db)
        result = management_provision(fixture, names, actor_url)
        if result.returncode == 0 and case == "aegaeon_management_authority_owner_inherit":
            # Old provisioning really exposes owned data to this unrelated login.
            # Observe only counts/key length, never the cursor key or credential bytes.
            with psycopg.connect(
                migrated_url.replace("postgres@", "management_unrelated@")
            ) as rogue:
                observed = rogue.execute(
                    "SELECT (SELECT count(*) FROM management_authority.grants),"
                    "(SELECT count(*) FROM management_authority.operation_receipts),"
                    "octet_length(cursor_key) FROM management_authority.installation"
                ).fetchone()
            raise AssertionError((case, "unauthorized login read owner data", observed))
        assert result.returncode != 0, (case, "unexpected membership accepted")
        assert (
            "unexpected member" in result.stderr
            or "incompatible management authority group" in result.stderr
        ), result.stderr
        assert membership_rows(db) == injected, "refusal silently changed role memberships"
    finally:
        db.execute("RESET ROLE")
        for group, member, _options, grantor in reversed(grants):
            db.execute(
                sql.SQL("REVOKE {} FROM {} GRANTED BY {} CASCADE").format(
                    sql.Identifier(group), sql.Identifier(member), sql.Identifier(grantor)
                )
            )
        assert membership_rows(db) == before, "owned injection cleanup changed other memberships"


def management_bootstrap(database_url, directory):
    suppliers = json.loads((directory / "suppliers.json").read_text())
    principal = uuid.uuid4()
    with psycopg.connect(database_url, autocommit=True) as db:
        installation = db.execute("SELECT id FROM management_authority.installation").fetchone()[0]
        db.execute(
            "INSERT INTO aegaeon.administrators(id,email,password_hash,kind) "
            "VALUES(%s,%s,'fixture','HUMAN')",
            (principal, str(principal) + "@example.invalid"),
        )
    request = {
        "installation_id": str(installation),
        "operation_id": str(uuid.uuid4()),
        "grant_id": str(uuid.uuid4()),
        "principal_id": str(principal),
        "principal_kind": "HUMAN",
        "adopt_installation": True,
        "permanent": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "conditions": {},
        "use_selector": {
            "id": str(uuid.uuid4()),
            "mode": "exact",
            "anchor_kind": "installation",
            "anchor_id": str(installation),
        },
        "use_actions": {
            "policy": "enumerated",
            "registry_version": 1,
            "actions": ["inventory.teams.read"],
        },
    }
    receipts = []
    with psycopg.connect(suppliers["urls"]["bootstrap"], autocommit=True) as db:
        for _ in range(2):
            with db.transaction():
                db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                receipts.append(
                    db.execute(
                        "SELECT management_authority.bootstrap_v1(%s)", (Jsonb(request),)
                    ).fetchone()[0]
                )
    assert receipts[0] == receipts[1]
    assert receipts[0]["grantId"] == request["grant_id"]


def verify_management_memberships(fixture, names, url, directory):
    migrated = url.replace("/postgres?", "/" + names["database"] + "?")
    failures = {}
    with psycopg.connect(url, autocommit=True) as db:
        db.execute("CREATE ROLE management_unrelated LOGIN")
        db.execute("CREATE ROLE management_unrelated_group NOLOGIN")
        for phase, target in (
            ("empty_database_existing_roles", url),
            ("after_migration", migrated),
        ):
            actor = target.replace("postgres@", "fixture_dba@")
            for _ in range(2):
                result = management_provision(fixture, names, actor)
                assert result.returncode == 0, result.stderr
            for case, grants in membership_cases(names):
                check_management_case(db, fixture, names, (actor, migrated), (case, grants))
                failures[phase + "_" + case] = "installer refused without changing memberships"
    management_bootstrap(migrated, directory)
    failures["management_bootstrap_replay"] = "dedicated bootstrap committed once and replayed"
    return failures


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
    management_refusals = verify_new_management_memberships(fixture, url)
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
    failures.update(management_refusals)
    failures.update(verify_management_memberships(fixture, names, url, directory))
    failures.update(
        verify_management_role_authority(fixture, names, url, directory, management_provision)
    )
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
        ("provision-management-authority.sql", args.management_provision),
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
        "management-provision",
        "atlas-config",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    records = [run_case(args, setting) for setting in ("", "set,inherit")]
    args.output.write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
