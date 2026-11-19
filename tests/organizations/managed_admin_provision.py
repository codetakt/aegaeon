"""Exercise absent and consolidated creator memberships using real PostgreSQL GRANTs."""

from __future__ import annotations

from functools import partial

import psycopg
from psycopg import sql

GROUPS = ("aegaeon_management_authority_owner", "aegaeon_management_bootstrap")


def memberships(db, member):
    return db.execute(
        "SELECT roleid::regrole::text,grantor::regrole::text,"
        "admin_option,inherit_option,set_option "
        "FROM pg_auth_members WHERE member=%s::regrole AND roleid IN (%s::regrole,%s::regrole) "
        "ORDER BY roleid::regrole::text,grantor",
        (member, *GROUPS),
    ).fetchall()


def check_same_grantor(db, url, migrated, provision):
    # Native superuser execution reproduces the provider's reported grantor attribution.
    # Exercise the same script with a real NOSUPERUSER below, separately.
    assert memberships(db, "postgres") == []
    # A refusal after adding the pair must roll back the new memberships too.
    db.execute("CREATE ROLE unexpected_managed_member")
    db.execute("GRANT aegaeon_management_bootstrap TO unexpected_managed_member")
    denied = provision(url, provisioning_admin="postgres")
    assert denied.returncode != 0
    assert "unexpected member" in denied.stderr
    assert memberships(db, "postgres") == []
    db.execute("REVOKE aegaeon_management_bootstrap FROM unexpected_managed_member")
    dry = provision(url, provisioning_admin="postgres", commit=False)
    assert dry.returncode == 0, dry.stderr
    assert memberships(db, "postgres") == []
    for target in (url, migrated, migrated):
        result = provision(target, provisioning_admin="postgres")
        assert result.returncode == 0, result.stderr
        assert memberships(db, "postgres") == [
            (GROUPS[0], "postgres", True, True, True),
            (GROUPS[1], "postgres", True, False, False),
        ]


def check_unrelated_member(db, migrated, provision):
    # A matching pair for another principal must not authorize that principal's mixed row.
    db.execute("CREATE ROLE managed_admin_test LOGIN CREATEROLE")
    db.execute(
        "GRANT aegaeon_management_authority_owner TO managed_admin_test "
        "WITH ADMIN TRUE, INHERIT TRUE, SET TRUE"
    )
    db.execute(
        "GRANT aegaeon_management_bootstrap TO managed_admin_test "
        "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
    )
    original = memberships(db, "managed_admin_test")
    denied = provision(migrated, provisioning_admin="postgres")
    assert denied.returncode != 0
    assert "unexpected member" in denied.stderr, denied.stderr
    assert memberships(db, "managed_admin_test") == original
    # Restore this fixture actor to the native two-ADMIN-only shape so the next
    # independently selected installer can be tested on the same migrated database.
    db.execute("GRANT aegaeon_management_authority_owner TO postgres WITH INHERIT FALSE, SET FALSE")
    return original


def check_restricted_installer(db, migration_role, migrated, provision, original):
    actor = migrated.replace("postgres@", "managed_admin_test@")
    db.execute(
        sql.SQL("GRANT {} TO managed_admin_test WITH INHERIT TRUE, SET TRUE").format(
            sql.Identifier(migration_role)
        )
    )
    spoof = provision(actor, provisioning_admin="postgres")
    assert spoof.returncode != 0
    assert "authenticated installation administrator" in spoof.stderr
    default = provision(actor)
    assert default.returncode != 0
    assert "unexpected member" in default.stderr, default.stderr
    for _ in range(2):
        result = provision(actor, provisioning_admin="managed_admin_test")
        assert result.returncode == 0, result.stderr
        assert set(original) <= set(memberships(db, "managed_admin_test"))

    db.execute("GRANT aegaeon_management_bootstrap TO managed_admin_test WITH SET TRUE")
    invalid = memberships(db, "managed_admin_test")
    denied = provision(actor, provisioning_admin="managed_admin_test")
    assert denied.returncode != 0
    assert "lacks verified administration" in denied.stderr
    assert memberships(db, "managed_admin_test") == invalid

    db.execute("CREATE ROLE managed_unprivileged LOGIN CREATEROLE")
    actor = migrated.replace("postgres@", "managed_unprivileged@")
    denied = provision(actor, provisioning_admin="managed_unprivileged")
    assert denied.returncode != 0
    assert memberships(db, "managed_unprivileged") == []


def verify_managed_admin(fixture, names, url, provision):
    migrated = url.replace("/postgres?", "/" + names["database"] + "?")
    provision = partial(provision, fixture, names)
    with psycopg.connect(migrated, autocommit=True) as db:
        check_same_grantor(db, url, migrated, provision)
        original = check_unrelated_member(db, migrated, provision)
        check_restricted_installer(db, names["migration"], migrated, provision, original)
    return {
        "managed_catalog_memberships": "absent pair, dry rollback, combined owner",
        "managed_catalog_reapplication": "same grantor before and after migration",
        "managed_catalog_authentication": "restricted installer and third-party refusals",
    }
