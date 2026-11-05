"""Actual full primary backup/restore and current revocation comparison."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest
from catalog_upgrade import SEED, seed_lti


def run(*args):
    result = subprocess.run(  # noqa: S603 — fixed test tools and owned paths
        args, capture_output=True, text=True, check=False, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return result


def main():  # noqa: PLR0915 — finite backup and mutation acceptance
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--operator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    sys.path.insert(0, str(args.operator / "share/aegaeon/scripts/operations"))
    import organization_restore_content as content  # noqa: PLC0415

    with psycopg.connect(dbname="postgres", autocommit=True) as administrator:
        administrator.execute(
            "CREATE ROLE aegaeon_subject_owner; CREATE ROLE aegaeon_subject_maintenance"
        )
    for name in ("restore_source", "restore_stale", "restore_current"):
        run("createdb", name)
    run("psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "restore_source", "-f", str(args.schema))
    with psycopg.connect(dbname="restore_source", autocommit=True) as source:
        source.execute(SEED)
        seed_lti("restore_source")
        source.execute("""
          CREATE SEQUENCE public.retained_sequence;
          SELECT nextval('public.retained_sequence');
          CREATE TABLE public.retained_duplicates(payload text NOT NULL);
          INSERT INTO public.retained_duplicates VALUES('same'),('same');
          INSERT INTO aegaeon.authorization_domains(id,environment_id,name,enabled)
          VALUES('00000000-0000-0000-0000-000000000020',
            '00000000-0000-0000-0000-000000000003','Domain',true);
          INSERT INTO aegaeon.application_organizations(
            id,environment_id,domain_id,external_id,state)
          SELECT gen_random_uuid(),'00000000-0000-0000-0000-000000000003',
            '00000000-0000-0000-0000-000000000020',name,'active'
          FROM unnest(ARRAY['Acme','acme','é','é','講義']) name;
          INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,
            end_user_id,incarnation,state,roles)
          SELECT environment_id,domain_id,id,'00000000-0000-0000-0000-000000000004',
            gen_random_uuid(),'active','["reader"]' FROM aegaeon.application_organizations
          WHERE external_id='Acme';
          UPDATE aegaeon.end_user_password_credentials SET password_hash='private-fixture-hash'
          WHERE end_user_id='00000000-0000-0000-0000-000000000004';
        """)
        run("pg_dump", "-Fc", "-f", str(args.output / "old.dump"), "restore_source")
        source.execute("""
          UPDATE aegaeon.organization_memberships
            SET state='removed',revision=2,grant_generation=2;
          UPDATE aegaeon.end_user_password_credentials SET status='REVOKED';
        """)
        run("pg_dump", "-Fc", "-f", str(args.output / "final.dump"), "restore_source")
        for target, backup in (("restore_stale", "old.dump"), ("restore_current", "final.dump")):
            run(
                "pg_restore",
                "--exit-on-error",
                "--single-transaction",
                "-d",
                target,
                str(args.output / backup),
            )
        with (
            psycopg.connect(dbname="restore_current", autocommit=True) as target,
            psycopg.connect(dbname="restore_stale", autocommit=True) as stale,
        ):
            result = content.compare(source, target)
            assert result["rows"] > 20
            assert result["activationAuthorized"] is False
            assert "private-fixture-hash" not in json.dumps(result)
            assert (
                source.execute(
                    "SELECT external_id FROM aegaeon.application_organizations "
                    'ORDER BY external_id COLLATE "C"'
                ).fetchall()
                == target.execute(
                    "SELECT external_id FROM aegaeon.application_organizations "
                    'ORDER BY external_id COLLATE "C"'
                ).fetchall()
            )
            with pytest.raises(Exception, match="differs from current source"):
                content.compare(source, stale)
            # Identical mismatch assertion must detect a removed equality guard.
            original = Path(content.__file__).read_text()
            guard = (
                'require(before == after, "restored primary content differs from current source")'
            )
            assert original.count(guard) == 1
            mutation = args.output / "comparison-removed.py"
            mutation.write_text(original.replace(guard, "# injected guard removal"))
            spec = importlib.util.spec_from_file_location("restore_mutant", mutation)
            mutant = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mutant)
            with (
                pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"),
                pytest.raises(Exception, match="differs from current source"),
            ):
                mutant.compare(source, stale)
            conditions = [
                "final full backup equality",
                "old revoked membership/password backup refused",
                "same mismatch assertion detects removed comparison",
            ]
            cases = [
                (
                    "UPDATE aegaeon.user_attribute_sources SET attribute_values='{}'",
                    (
                        "UPDATE aegaeon.user_attribute_sources SET attribute_values="
                        '\'{"name":"保存値","number":18446744073709551615,"nested":{"__proto__":null}}\''
                    ),
                    "attribute value",
                ),
                (
                    (
                        "DELETE FROM public.retained_duplicates WHERE ctid IN "
                        "(SELECT ctid FROM public.retained_duplicates LIMIT 1)"
                    ),
                    "INSERT INTO public.retained_duplicates VALUES('same')",
                    "duplicate row loss",
                ),
                (
                    "SELECT setval('public.retained_sequence',1,false)",
                    "SELECT setval('public.retained_sequence',1,true)",
                    "sequence is-called rewind",
                ),
                ("CREATE TABLE public.extra(id bigint)", "DROP TABLE public.extra", "extra table"),
            ]
            for change, undo, label in cases:
                target.execute(change)
                with pytest.raises(Exception, match="differs from current source"):
                    content.compare(source, target)
                target.execute(undo)
                conditions.append(label + " refused")
            for setup, cleanup, message in [
                ("CREATE SCHEMA unknown", "DROP SCHEMA unknown", "unsupported schema"),
                (
                    "CREATE UNLOGGED TABLE public.unsafe(id int)",
                    "DROP TABLE public.unsafe",
                    "unsupported primary relation",
                ),
                (
                    "SELECT lo_create(0)",
                    "SELECT lo_unlink(oid) FROM pg_largeobject_metadata",
                    "large object",
                ),
            ]:
                target.execute(setup)
                with pytest.raises(Exception, match=message):
                    content.observe(target)
                target.execute(cleanup)
                conditions.append(message + " refused")
            for field, value, message in [
                ("MAX_ROWS", 0, "row count budget"),
                ("MAX_ROW_BYTES", 1, "row byte budget"),
                ("MAX_DATABASE_BYTES", 1, "database byte budget"),
                ("MAX_RELATIONS", 1, "relation budget"),
            ]:
                saved = getattr(content, field)
                setattr(content, field, value)
                try:
                    with pytest.raises(Exception, match=message):
                        content.observe(source)
                finally:
                    setattr(content, field, saved)
                conditions.append(message + " refused")
            assert content.compare(source, target) == result
            (args.output / "result.json").write_text(
                json.dumps(
                    {
                        "status": "passed",
                        "result": result,
                        "conditions": conditions,
                        "newCompositeDischarges": 0,
                        "scope": (
                            "actual primary data component; no operator/control supplier acceptance"
                        ),
                    },
                    indent=2,
                )
                + "\n"
            )
    # Backups contain fixture credentials; do not publish their contents as receipts.
    for file in ("old.dump", "final.dump"):
        (args.output / file).unlink()


if __name__ == "__main__":
    main()
