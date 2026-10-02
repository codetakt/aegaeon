#!/usr/bin/env python3
"""Own one disposable database and restricted logins for required server tests."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]


def execute(argv: list[str], *, data: str | None = None, env: dict[str, str] | None = None) -> None:
    # Callers use fixed pinned-shell tools and argument lists; no shell evaluation.
    subprocess.run(argv, cwd=ROOT, input=data, text=True, env=env, check=True)  # noqa: S603


def postgres_environment(url: str) -> dict[str, str]:
    # PGDATABASE alone treats a URI as a database name. Keep credentials out of
    # command arguments by supplying the individual libpq environment settings.
    parsed = urlsplit(url)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname:
        message = "test database URL must be a PostgreSQL URL with a host"
        raise ValueError(message)
    values = {"PGHOST": parsed.hostname, "PGDATABASE": unquote(parsed.path.removeprefix("/"))}
    for name, value in (
        ("PGPORT", parsed.port),
        ("PGUSER", parsed.username),
        ("PGPASSWORD", parsed.password),
    ):
        if value is not None:
            values[name] = unquote(str(value))
    query_settings = {
        "host": "PGHOST",
        "port": "PGPORT",
        "sslmode": "PGSSLMODE",
        "sslcert": "PGSSLCERT",
        "sslkey": "PGSSLKEY",
        "sslrootcert": "PGSSLROOTCERT",
        "sslcrl": "PGSSLCRL",
        "connect_timeout": "PGCONNECT_TIMEOUT",
        "options": "PGOPTIONS",
        "application_name": "PGAPPNAME",
        "channel_binding": "PGCHANNELBINDING",
        "target_session_attrs": "PGTARGETSESSIONATTRS",
    }
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key in ("user", "password", "dbname"):
            message = "test database URL query must not override user, password or dbname"
            raise ValueError(message)
        if key not in query_settings:
            message = "unsupported test database URL query setting"
            raise ValueError(message)
        values[query_settings[key]] = value
    return os.environ | values


def psql(url: str, text: str) -> None:
    execute(["psql", "-X", "-v", "ON_ERROR_STOP=1"], data=text, env=postgres_environment(url))


def connection(admin: str, user: str, password: str, database: str) -> str:
    postgres_environment(admin)
    parsed = urlsplit(admin)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname:
        message = "test administrator URL must be a PostgreSQL URL with a host"
        raise ValueError(message)
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    authority = f"{quote(user, safe='')}:{quote(password, safe='')}@{host}"
    if parsed.port:
        authority += f":{parsed.port}"
    return urlunsplit((parsed.scheme, authority, "/" + database, parsed.query, ""))


def prepare(directory: Path, admin: str) -> None:
    postgres_environment(admin)
    # The caller creates this new private directory. Save owned resource names
    # before DDL so failure cleanup never guesses or touches unrelated resources.
    suffix = secrets.token_hex(8)
    names = {
        kind: f"aegaeon_test_{kind}_{suffix}"
        for kind in ("database", "migration", "runtime", "maintenance")
    }
    (directory / "owned-resources.json").write_text(json.dumps(names) + "\n")
    passwords = {
        kind: secrets.token_urlsafe(32) for kind in ("migration", "runtime", "maintenance")
    }
    # Names and passwords are generated from fixed safe alphabets. Do not echo
    # credential-bearing DDL or command arguments to shared CI output.
    statements = [
        f"CREATE ROLE {names[kind]} LOGIN PASSWORD '{passwords[kind]}';" for kind in passwords
    ]
    statements.append(f"CREATE DATABASE {names['database']} OWNER {names['migration']};")
    private_log = directory / "setup.log"
    with private_log.open("w") as log:
        result = subprocess.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1"],  # noqa: S607 - pinned dev-shell tool
            cwd=ROOT,
            input="\n".join(statements),
            text=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=postgres_environment(admin),
            check=False,
        )
    if result.returncode:
        message = f"disposable database creation failed; private log: {private_log}"
        raise RuntimeError(message)
    urls = {
        kind: connection(admin, names[kind], passwords[kind], names["database"])
        for kind in passwords
    }
    admin_db = urlsplit(admin)._replace(path="/" + names["database"]).geturl()
    (directory / "suppliers.json").write_text(json.dumps({"names": names, "urls": urls}) + "\n")
    (directory / "suppliers.json").chmod(0o600)
    configure_database(names, urls, admin_db, run_pre_migration_tests=True)
    env_file = directory / "runtime-env.sh"
    env_file.write_text(
        "export AEGAEON_DATABASE_URL=" + shlex.quote(urls["runtime"]) + "\n"
        "export DATABASE_URL=" + shlex.quote(urls["runtime"]) + "\n"
        "export AEGAEON_TEST_DATABASE_FIXTURE_DIRECTORY=" + shlex.quote(str(directory)) + "\n"
    )
    env_file.chmod(0o600)


def configure_database(
    names: dict[str, str], urls: dict[str, str], admin_db: str, *, run_pre_migration_tests: bool
) -> None:
    provision = [
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
        "-v",
        "commit=true",
        "-f",
        "scripts/operations/provision-subject-ownership.sql",
    ]
    execute(provision, env=postgres_environment(admin_db))
    migrations = sorted((ROOT / "db/migrations").glob("*.sql"))
    predecessor_count = next(
        i
        for i, path in enumerate(migrations)
        if path.name == "20261002130000_subject_ownership.sql"
    )
    atlas = [
        "atlas",
        "migrate",
        "apply",
        "--dir",
        "file://db/migrations",
        "--revisions-schema",
        "public",
        "--env",
        "local",
    ]
    execute([*atlas, str(predecessor_count)], env=os.environ | {"DATABASE_URL": urls["migration"]})
    if run_pre_migration_tests:
        execute(
            [
                "cargo",
                "test",
                "-p",
                "aegaeon-server",
                "--lib",
                "pre_migration_",
                "--",
                "--ignored",
                "--test-threads=1",
            ],
            env=os.environ | {"AEGAEON_PRE_MIGRATION_DATABASE_URL": urls["migration"]},
        )
    execute(atlas, env=os.environ | {"DATABASE_URL": urls["migration"]})
    execute(provision, env=postgres_environment(admin_db))
    runtime = names["runtime"]
    psql(
        admin_db,
        f"""
GRANT USAGE ON SCHEMA aegaeon TO {runtime};
DO $fixture$ DECLARE r record; BEGIN
FOR r IN SELECT c.relname,c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='aegaeon' AND c.relkind IN ('r','p','v')
AND c.relname NOT IN ('subject_ownership_namespaces','subject_ownership_adoptions',
'end_user_identity_owners','end_user_subject_reservations') LOOP
IF r.relkind='v' THEN EXECUTE format('GRANT SELECT ON aegaeon.%I TO {runtime}',r.relname);
ELSE EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON aegaeon.%I TO {runtime}',r.relname);
END IF;
END LOOP; END $fixture$;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA aegaeon TO {runtime};
""",  # noqa: S608 - runtime is a fixture-generated role identifier
    )
    # Check final ordinary grants as well; adding application fixture permissions
    # must not widen permanent ownership or maintenance authority.
    execute(provision, env=postgres_environment(admin_db))


def prepare_child(name: str, admin: str) -> None:
    postgres_environment(admin)
    if not name.startswith("initialization_") or not all(
        c.islower() or c.isdigit() or c == "_" for c in name
    ):
        message = "invalid owned initialization database name"
        raise ValueError(message)
    directory = Path(os.environ["AEGAEON_TEST_DATABASE_FIXTURE_DIRECTORY"])
    suppliers = json.loads((directory / "suppliers.json").read_text())
    names = suppliers["names"] | {"database": name}
    urls = {
        kind: urlsplit(url)._replace(path="/" + name).geturl()
        for kind, url in suppliers["urls"].items()
    }
    # Record ownership before DDL; parent cleanup covers setup/test failures.
    children = directory / "owned-children.json"
    recorded = json.loads(children.read_text()) if children.exists() else []
    if name in recorded:
        message = "child database name was already registered"
        raise ValueError(message)
    children.write_text(json.dumps([*recorded, name]) + "\n")
    psql(admin, f"CREATE DATABASE {name} OWNER {names['migration']};")
    admin_db = urlsplit(admin)._replace(path="/" + name).geturl()
    configure_database(names, urls, admin_db, run_pre_migration_tests=False)


def cleanup(directory: Path, admin: str) -> None:
    record = directory / "owned-resources.json"
    if not record.exists():
        return
    names = json.loads(record.read_text())
    # Only resources generated and recorded by this invocation are removed.
    for value in names.values():
        if not value.startswith("aegaeon_test_") or not all(
            c.islower() or c.isdigit() or c == "_" for c in value
        ):
            message = "invalid owned fixture identifier"
            raise ValueError(message)
    children = directory / "owned-children.json"
    for child in json.loads(children.read_text()) if children.exists() else []:
        if not child.startswith("initialization_") or not all(
            c.islower() or c.isdigit() or c == "_" for c in child
        ):
            message = "invalid owned child database identifier"
            raise ValueError(message)
        psql(admin, f"DROP DATABASE IF EXISTS {child} WITH (FORCE);")
    psql(admin, f"DROP DATABASE IF EXISTS {names['database']} WITH (FORCE);")
    for kind in ("runtime", "maintenance", "migration"):
        psql(admin, f"DROP ROLE IF EXISTS {names[kind]};")
    (directory / "runtime-env.sh").unlink(missing_ok=True)
    (directory / "suppliers.json").unlink(missing_ok=True)
    (directory / "disposition.json").write_text(
        json.dumps(
            {
                "database": "removed",
                "login_roles": "removed",
                "namespace_lifetime": "whole owned database",
            }
        )
        + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "prepare-child", "cleanup"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    admin = os.environ["AEGAEON_TEST_ADMIN_DATABASE_URL"]
    if args.operation == "prepare":
        prepare(args.directory, admin)
    elif args.operation == "prepare-child":
        prepare_child(str(args.directory), admin)
    else:
        cleanup(args.directory, admin)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, RuntimeError, ValueError, KeyError) as error:
        # CalledProcessError can include credential-bearing environment/arguments;
        # expose fixed text and keep setup details in the private fixture directory.
        print(
            "Subject ownership test database fixture failed (" + type(error).__name__ + ").",
            file=sys.stderr,
        )
        sys.exit(1)
