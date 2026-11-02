"""Real PostgreSQL upgrade and catalog-composition regression; no serving claim."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import psycopg

SEED = """
        INSERT INTO aegaeon.teams(id,name,slug) VALUES
          ('00000000-0000-0000-0000-000000000001','Fixture','fixture');
        INSERT INTO aegaeon.tenants(id,team_id,slug,name,region) VALUES
          ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001','tenant','Tenant','local');
        INSERT INTO aegaeon.environments(id,tenant_id,name,slug,issuer_host) VALUES
          ('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002','Environment','environment','issuer.example');
        INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES
          ('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000003','persistent-owner','ACTIVE');
        INSERT INTO aegaeon.user_attribute_sources(environment_id,end_user_id,source_namespace,
          source_kind,source_authority,source_revision,observed_at,attribute_values,revision) VALUES
          ('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004',
           'local','LOCAL','administrator:fixture','17',1,
           '{"name":"保存値", "number":18446744073709551615,"nested":{"__proto__":null}}',17);
    """
PRESERVED = """SELECT jsonb_build_object(
        'attributes',(SELECT jsonb_agg(to_jsonb(a)) FROM aegaeon.user_attribute_sources a),
        'owners',(SELECT jsonb_agg(to_jsonb(o)) FROM aegaeon.end_user_identity_owners o),
        'subjects',(SELECT jsonb_agg(to_jsonb(s)) FROM aegaeon.end_user_subject_reservations s),
        'identity',(SELECT jsonb_agg(jsonb_build_array(
            id,environment_id,subject,status,created_at,updated_at)) FROM aegaeon.end_users))::text
"""
PREFLIGHT = "SELECT aegaeon.subject_history_preflight('catalog_runtime')"
PHYSICAL = "SELECT aegaeon.subject_history_observed_physical()"
REVISIONS = "SELECT version,hash FROM public.atlas_schema_revisions ORDER BY version"
FINAL = "20261102103000_lti_admission_inventory.sql"
CORRUPTIONS = [
    (
        "ALTER TABLE aegaeon.user_attribute_sources DROP CONSTRAINT "
        "user_attribute_sources_environment_id_end_user_id_fkey"
    ),
    "ALTER TABLE aegaeon.user_attribute_sources ENABLE ROW LEVEL SECURITY",
    (
        "ALTER TABLE aegaeon.lti_launch_intents DROP CONSTRAINT "
        "lti_launch_intents_environment_id_registration_id_fkey"
    ),
    "DROP INDEX aegaeon.lti_launch_intents_expiry_idx",
    "DROP INDEX aegaeon.lti_launch_intents_admission_idx",
    "ALTER TABLE aegaeon.lti_identifiers DISABLE TRIGGER lti_identifier_immutable",
    "ALTER FUNCTION aegaeon.lti_immutable_record() RESET search_path",
    "ALTER TABLE aegaeon.lti_launch_intents ENABLE ROW LEVEL SECURITY",
    "GRANT TRIGGER ON aegaeon.user_attribute_sources TO catalog_runtime",
    "GRANT SELECT ON aegaeon.user_attribute_sources TO catalog_maintenance",
    (
        "UPDATE public.atlas_schema_revisions SET hash=repeat('x',43)||'=' "
        "WHERE version='20261101090000'"
    ),
    "DELETE FROM public.atlas_schema_revisions WHERE version='20261102101000'",
]


def sql(database, statement):
    with (
        psycopg.connect(dbname=database, autocommit=True) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(statement)
        return cursor.fetchall() if cursor.description else None


class Fixture:
    def __init__(self, args, log):
        self.args = args
        self.log = log
        self.inventory = json.loads(args.baseline.read_text())

    def run(self, command, *, env=None, succeeds=True):
        # Fixed test tools/arguments; paths are supplied by the Nix derivation.
        result = subprocess.run(  # noqa: S603
            command, env=env, capture_output=True, text=True, timeout=60, check=False
        )
        self.log.write(result.stdout + result.stderr)
        self.log.flush()
        assert (result.returncode == 0) == succeeds, (command[0], result.returncode)
        return result.stdout + result.stderr

    def provision(self, database):
        self.run(
            [
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-v",
                "runtime_role=catalog_runtime",
                "-v",
                "migration_role=catalog_migration",
                "-v",
                "maintenance_role=catalog_maintenance",
                "-v",
                "commit=true",
                "-f",
                str(self.args.provision),
            ],
            env=os.environ | {"PGDATABASE": database},
        )

    def migrate(self, database, directory, *, non_linear=False, succeeds=True):
        url = (
            f"postgresql://catalog_migration@/{database}?host={os.environ['PGHOST']}"
            "&sslmode=disable"
        )
        command = [
            "atlas",
            "migrate",
            "apply",
            "--url",
            url,
            "--dir",
            f"file://{directory}",
            "--revisions-schema",
            "public",
            "--lock-timeout",
            "5s",
        ]
        if non_linear:
            command += ["--exec-order", "non-linear"]
        return self.run(command, succeeds=succeeds)

    def setup(self):
        baseline = Path(os.environ["TMPDIR"]) / "baseline-migrations"
        baseline.mkdir()
        for item in self.inventory["files"]:
            source = self.args.migrations / item["name"]
            assert hashlib.sha256(source.read_bytes()).hexdigest() == item["sha256"]
            shutil.copyfile(source, baseline / item["name"])
        sql(
            "postgres",
            "CREATE ROLE catalog_migration LOGIN; "
            "CREATE ROLE catalog_runtime LOGIN; CREATE ROLE catalog_maintenance LOGIN;",
        )
        for name in ["upgraded", "fresh", "from_schema"]:
            sql("postgres", f"CREATE DATABASE {name} OWNER catalog_migration")
            self.provision(name)
        self.run(["atlas", "migrate", "hash", "--dir", f"file://{baseline}"])
        self.migrate("upgraded", baseline)
        self.provision("upgraded")
        sql("upgraded", SEED)

    def upgrade(self):
        before = sql("upgraded", PRESERVED)
        revisions = sql("upgraded", REVISIONS)
        self.migrate("upgraded", self.args.migrations)
        assert sql("upgraded", REVISIONS)[: len(revisions)] == revisions
        assert sql("upgraded", PRESERVED) == before
        self.provision("upgraded")
        self.migrate("fresh", self.args.migrations)
        self.provision("fresh")
        assert sql("upgraded", PHYSICAL) == sql("fresh", PHYSICAL)
        assert sql("upgraded", PREFLIGHT) == sql("fresh", PREFLIGHT)
        return before

    def predecessors(self):
        # Actual earlier checkers fail on the combined database; no simulated result.
        rejected = []
        for name in [
            "20261029052000_subject_prerequisite_catalog.sql",
            "20261101090000_user_attribute_sources.sql",
            "20261102101000_lti_subject_inventory.sql",
            FINAL,
        ]:
            source = (self.args.migrations / name).read_text()
            definition = re.search(
                r"CREATE OR REPLACE FUNCTION aegaeon.subject_history_preflight\(.*?\$function\$;",
                source,
                re.DOTALL,
            ).group()
            sql("upgraded", definition)
            observed_error = None
            try:
                sql("upgraded", PREFLIGHT)
            except psycopg.errors.RaiseException as error:
                observed_error = str(error)
            if name == FINAL:
                assert observed_error is None
            else:
                assert observed_error is not None
                assert any(
                    message in observed_error
                    for message in [
                        "subject physical schema or trigger definition mismatch",
                        "unexpected or duplicate Atlas revision",
                    ]
                )
                rejected.append(name)
        assert len(rejected) == 3
        return rejected

    def schema(self):
        # Physical shape only: never invent an Atlas history for the schema artifact.
        self.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-f", str(self.args.schema)],
            env=os.environ | {"PGDATABASE": "from_schema"},
        )
        assert sql("from_schema", PHYSICAL) == sql("fresh", PHYSICAL)


def corruptions():
    for corruption in CORRUPTIONS:
        with psycopg.connect(dbname="upgraded") as connection:
            with connection.cursor() as cursor:
                cursor.execute(corruption)
                try:
                    cursor.execute(PREFLIGHT)
                except (psycopg.errors.RaiseException, psycopg.errors.InsufficientPrivilege):
                    pass
                else:
                    raise AssertionError(corruption)
            connection.rollback()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["migrations", "schema", "provision", "baseline", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    with (args.output / "operations.log").open("w") as log:
        fixture = Fixture(args, log)
        fixture.setup()
        before = fixture.upgrade()
        rejected = fixture.predecessors()
        corruptions()
        assert sql("upgraded", PRESERVED) == before
        fixture.schema()
        result = {
            "main_baseline": fixture.inventory["revision"],
            "main_migrations": len(fixture.inventory["files"]),
            "final_migrations": len(list(args.migrations.glob("*.sql"))),
            "fresh_and_upgrade_catalogs_equal": True,
            "schema_physical_equal": True,
            "retained_attribute_provenance_and_identity": True,
            "linear_upgrade_preserves_old_ledger": True,
            "predecessor_checkers_rejected": rejected,
            "corruptions_rejected": CORRUPTIONS,
            "scope": "PostgreSQL catalog/migration tests; not runtime or product assurance",
        }
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
