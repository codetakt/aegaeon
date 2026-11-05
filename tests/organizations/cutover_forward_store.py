"""Owned fourth-cluster backups; current source stays excluded throughout."""

from __future__ import annotations

import os
import subprocess
from contextlib import ExitStack
from pathlib import Path

import psycopg
import pytest
from psycopg import sql


def client(configuration, *, database=None):
    import organization_recovery as recovery  # noqa: PLC0415

    return {
        "host": configuration["host"],
        "port": configuration["port"],
        "dbname": database or configuration["dbname"],
        "user": configuration["user"],
        "password": recovery.private_file(configuration["password_file"]).decode(),
        "sslrootcert": configuration["ca_file"],
        "sslmode": "verify-full",
        "connect_timeout": 5,
        "autocommit": True,
    }


def pg(fixture, configuration, name, *arguments, data=None, database=None):
    selected = client(configuration, database=database)
    environment = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    for key, value in selected.items():
        if key not in ("autocommit", "connect_timeout"):
            environment["PG" + ("DATABASE" if key == "dbname" else key.upper())] = str(value)
    environment["PGCONNECT_TIMEOUT"] = "5"
    result = subprocess.run(  # noqa: S603 — exact pinned client, private credentials only in environment
        [str(Path(fixture["postgres_bin"]) / name), *map(str, arguments)],
        env=environment,
        input=data,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (name, result.returncode, result.stderr)
    return result.stdout


def identity(configuration):
    with psycopg.connect(**client(configuration)) as connection:
        return connection.execute(
            "SELECT jsonb_build_object('cluster',system_identifier::text,"
            "'database',current_database(),'database_oid',"
            "(SELECT oid::bigint FROM pg_database WHERE datname=current_database())) "
            "FROM pg_control_system()"
        ).fetchone()[0]


def restore(fixture, archive):
    pg(
        fixture,
        fixture["connection"],
        "pg_restore",
        "--exit-on-error",
        "--create",
        "--dbname=postgres",
        archive,
        database="postgres",
    )


def current_backup(directory, fixture, source):
    roles = pg(fixture, source["connection"], "pg_dumpall", "--roles-only")
    roles = "\n".join(line for line in roles.splitlines() if line != "CREATE ROLE postgres;")
    pg(
        fixture,
        fixture["connection"],
        "psql",
        "-Xq",
        "-v",
        "ON_ERROR_STOP=1",
        data=roles,
        database="postgres",
    )
    archive = directory / "forward-current.dump"
    pg(fixture, source["connection"], "pg_dump", "-Fc", "--file", archive)
    archive.chmod(0o600)
    return archive


def negative_then_current(directory, fixture, inspection, accepted):
    import organization_recovery as recovery  # noqa: PLC0415
    import organization_restore_inspect as inspect  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    source = inspection["stores"][1]
    archive = current_backup(directory, fixture, source)
    restore(fixture, directory / "pre-write.dump")
    target = {
        "kind": "primary",
        "identity": identity(fixture["connection"]),
        "old_logins": source["old_logins"],
        "connection": fixture["connection"],
    }
    inspection["stores"].append(target)
    with ExitStack() as stack:
        stores = [recovery.connect(stack, value) for value in inspection["stores"]]
        assert (
            stores[1].one(
                "SELECT external_id FROM aegaeon.application_organizations WHERE id=%s",
                (accepted["organizationId"],),
            )
            == accepted["externalId"]
        )
        assert not stores[2].one(
            "SELECT EXISTS(SELECT FROM aegaeon.application_organizations WHERE id=%s)",
            (accepted["organizationId"],),
        )
        with pytest.raises(RecoveryRefusedError, match=r"primary .* differ"):
            inspect.inspect(inspection, stores)
    with psycopg.connect(**client(fixture["connection"], database="postgres")) as connection:
        connection.execute(
            sql.SQL("DROP DATABASE {}").format(sql.Identifier(target["identity"]["database"]))
        )
    restore(fixture, archive)
    target["identity"] = identity(fixture["connection"])
    with ExitStack() as stack:
        stores = [recovery.connect(stack, value) for value in inspection["stores"]]
        result = inspect.inspect(inspection, stores)
        assert result["activationAuthorized"] is False
        assert (
            stores[2].one(
                "SELECT external_id FROM aegaeon.application_organizations WHERE id=%s",
                (accepted["organizationId"],),
            )
            == accepted["externalId"]
        )
    return result
