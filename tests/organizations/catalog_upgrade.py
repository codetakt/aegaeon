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
        INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash,status)
          VALUES('00000000-0000-0000-0000-000000000004','unusable-retained-fixture-hash','ACTIVE');
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
        'passwords',(SELECT jsonb_agg(to_jsonb(p)) FROM aegaeon.end_user_password_credentials p),
        'identity',(SELECT jsonb_agg(jsonb_build_array(
            id,environment_id,subject,status,created_at,updated_at)) FROM aegaeon.end_users))::text
"""
PREFLIGHT = "SELECT aegaeon.subject_history_preflight('catalog_runtime')"
PHYSICAL = "SELECT aegaeon.subject_history_observed_physical()"
REVISIONS = "SELECT version,hash FROM public.atlas_schema_revisions ORDER BY version"
RUNTIME_SHAPE = """SELECT jsonb_build_object(
  'columns',(SELECT jsonb_agg(jsonb_build_array(table_schema,table_name,column_name,
    data_type,udt_name,is_nullable,column_default)
    ORDER BY table_schema,table_name,ordinal_position)
    FROM information_schema.columns WHERE table_schema='aegaeon_lifecycle'
      OR (table_schema='aegaeon' AND table_name LIKE 'runtime_%')),
  'constraints',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,k.conname,
    pg_get_constraintdef(k.oid,false)) ORDER BY n.nspname,c.relname,k.conname)
    FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='aegaeon_lifecycle' OR (n.nspname='aegaeon' AND c.relname LIKE 'runtime_%')),
  'indexes',(SELECT jsonb_agg(jsonb_build_array(schemaname,tablename,indexname,indexdef)
    ORDER BY schemaname,tablename,indexname) FROM pg_indexes WHERE schemaname='aegaeon_lifecycle'
    OR (schemaname='aegaeon' AND tablename LIKE 'runtime_%')),
  'functions',(SELECT jsonb_agg(jsonb_build_array(
    n.nspname,p.proname,p.prosrc,p.proconfig,p.prosecdef)
    ORDER BY n.nspname,p.proname) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='aegaeon_lifecycle'
    OR (n.nspname='aegaeon' AND p.proname='consume_runtime_security_budget')))
"""
FINAL = "20261105000000_organizations.sql"
MANAGEMENT = "20261106010000_management_authority.sql"
CORRUPTIONS = [
    (
        "ALTER TABLE aegaeon.user_attribute_sources DROP CONSTRAINT "
        "user_attribute_sources_environment_id_end_user_id_fkey"
    ),
    "ALTER TABLE aegaeon.user_attribute_sources ENABLE ROW LEVEL SECURITY",
    (
        "ALTER TABLE aegaeon.organization_memberships DROP CONSTRAINT "
        "organization_memberships_end_user_id_environment_id_fkey"
    ),
    "DROP INDEX aegaeon.authorization_domains_one_default",
    "DROP INDEX aegaeon.lti_launch_intents_admission_idx",
    "ALTER TABLE aegaeon.lti_identifiers DISABLE TRIGGER lti_identifier_immutable",
    "ALTER FUNCTION aegaeon.lti_immutable_record() RESET search_path",
    "GRANT SELECT ON aegaeon.lti_registrations TO catalog_maintenance",
    "ALTER TABLE aegaeon.lti_launch_intents ENABLE ROW LEVEL SECURITY",
    "GRANT TRIGGER ON aegaeon.user_attribute_sources TO catalog_runtime",
    "GRANT SELECT ON aegaeon.user_attribute_sources TO catalog_maintenance",
    (
        "UPDATE public.atlas_schema_revisions SET hash=repeat('x',43)||'=' "
        "WHERE version='20261101090000'"
    ),
    "DELETE FROM public.atlas_schema_revisions WHERE version='20261105000000'",
    "ALTER TABLE management_authority.grants ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE management_authority.installation OWNER TO catalog_migration",
    "ALTER TABLE management_authority.selector_members DROP CONSTRAINT selector_members_pkey",
    "ALTER TABLE management_authority.grants DISABLE TRIGGER ALL",
    "ALTER TABLE aegaeon.teams DISABLE TRIGGER management_resource_identity",
    "DROP TRIGGER management_resource_identity ON aegaeon.teams",
    "ALTER TABLE aegaeon.tenants DISABLE TRIGGER management_resource_identity",
    "DROP TRIGGER management_resource_identity ON aegaeon.tenants",
    "ALTER TABLE aegaeon.administrators DISABLE TRIGGER management_principal_identity",
    "DROP TRIGGER management_principal_identity ON aegaeon.administrators",
    "ALTER FUNCTION management_authority.inventory_v1(jsonb) RESET search_path",
    "GRANT SELECT ON management_authority.installation TO catalog_runtime",
    "GRANT EXECUTE ON FUNCTION management_authority.bootstrap_v1(jsonb) TO catalog_runtime",
    "DELETE FROM public.atlas_schema_revisions WHERE version='20261106010000'",
]


def sql(database, statement):
    with (
        psycopg.connect(dbname=database, autocommit=True) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(statement)
        return cursor.fetchall() if cursor.description else None


def connection_reader_privileges(database):
    # Import dependency inspection needs these non-secret columns. Compare
    # effective column rights, including inherited/table-wide grants, so a
    # missing grant and accidental exposure of encrypted credentials both fail.
    columns = {
        "id",
        "environment_id",
        "configuration_version_id",
        "connection_identifier",
        "connection_type",
        "issuer_url",
        "client_id",
        "client_auth_method",
        "status",
        "deleted_at",
    }
    observed = sql(
        database,
        """
        SELECT role_name, a.attname,
          has_column_privilege(role_name, a.attrelid, a.attnum, 'SELECT')
        FROM pg_attribute a CROSS JOIN
          unnest(ARRAY['aegaeon_subject_owner','catalog_maintenance']) role_name
        WHERE a.attrelid='aegaeon.connections'::regclass
          AND a.attnum > 0 AND NOT a.attisdropped
        ORDER BY role_name, a.attname
    """,
    )
    assert {
        column for role, column, allowed in observed if role == "aegaeon_subject_owner" and allowed
    } == columns
    assert not any(allowed for role, _, allowed in observed if role == "catalog_maintenance")
    return observed


def seed_lti(database):
    if not sql(database, "SELECT to_regclass('aegaeon.lti_registrations') IS NOT NULL")[0][0]:
        return
    sql(
        database,
        """
      INSERT INTO aegaeon.configuration_versions(id,environment_id,version_number,
        configuration_hash,configuration_document)
      VALUES('00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000003',1,'fixture','{}');
      INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,
        client_identifier,name,client_type,
        redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method)
      VALUES('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000003',
        '00000000-0000-0000-0000-000000000010','tool','Tool','PUBLIC','{https://tool.example/launch}','{authorization_code}','{openid}','none');
      INSERT INTO aegaeon.administrators(id,email,password_hash)
      VALUES('00000000-0000-0000-0000-000000000012','catalog@example.com','unusable');
      INSERT INTO aegaeon.lti_registrations(id,environment_id,client_record_id,client_id,revision)
      VALUES('00000000-0000-0000-0000-000000000013','00000000-0000-0000-0000-000000000003',
        '00000000-0000-0000-0000-000000000011','tool',1);
      INSERT INTO aegaeon.lti_registration_revisions(registration_id,revision,document,author_id)
      VALUES('00000000-0000-0000-0000-000000000013',1,'{"status":"disabled","name":"保存値"}',
        '00000000-0000-0000-0000-000000000012');
      INSERT INTO aegaeon.lti_identifiers(environment_id,kind,identifier,
        registration_id,deployment_id)
      SELECT '00000000-0000-0000-0000-000000000003','deployment',id,
        '00000000-0000-0000-0000-000000000013',id FROM unnest(ARRAY['Course','course','講義']) id;
      INSERT INTO aegaeon.lti_launch_intents(environment_id,registration_id,revision,
        runtime_revision,
        runtime_fingerprint,owner_id,subject,producer_client_id,producer_token_digest,producer_metadata,
        deployment_id,resource_link_id,roles,ticket_hash,status,created_at,expires_at)
      VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000013',1,
        '00000000-0000-0000-0000-000000000014','fixture','00000000-0000-0000-0000-000000000004',
        'persistent-owner','producer','unusable','{}','講義','resource','[]','unusable','cancelled',1,301);
    """,
    )


def preserved(database):
    core = sql(database, PRESERVED)
    available = sql(database, "SELECT to_regclass('aegaeon.lti_registrations') IS NOT NULL")[0][0]
    lti = {}
    for table in [
        "lti_registrations",
        "lti_registration_revisions",
        "lti_identifiers",
        "lti_launch_intents",
    ]:
        query = psycopg.sql.SQL(
            'SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text COLLATE "C") FROM {} t'
        ).format(psycopg.sql.Identifier("aegaeon", table))
        lti[table] = sql(database, query)[0][0] if available else None
    return {"core": core, "lti": lti}


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
        self.run(
            [
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-v",
                "serving_role=catalog_runtime",
                "-v",
                "migration_role=catalog_migration",
                "-v",
                "bootstrap_role=catalog_bootstrap",
                "-v",
                "commit=true",
                "-f",
                str(self.args.management_provision),
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
        baseline_names = {item["name"] for item in self.inventory["files"]}
        candidate_names = {path.name for path in self.args.migrations.glob("*.sql")}
        assert candidate_names - baseline_names == {FINAL, MANAGEMENT}
        assert baseline_names <= candidate_names
        baseline = Path(os.environ["TMPDIR"]) / "baseline-migrations"
        baseline.mkdir()
        for item in self.inventory["files"]:
            source = self.args.migrations / item["name"]
            assert hashlib.sha256(source.read_bytes()).hexdigest() == item["sha256"]
            shutil.copyfile(source, baseline / item["name"])
        sql(
            "postgres",
            "CREATE ROLE catalog_migration LOGIN; "
            "CREATE ROLE catalog_runtime LOGIN; CREATE ROLE catalog_maintenance LOGIN; "
            "CREATE ROLE catalog_bootstrap LOGIN;",
        )
        for name in ["upgraded", "fresh", "from_schema"]:
            sql("postgres", f"CREATE DATABASE {name} OWNER catalog_migration")
            self.provision(name)
        self.run(["atlas", "migrate", "hash", "--dir", f"file://{baseline}"])
        self.migrate("upgraded", baseline)
        self.provision("upgraded")
        sql("upgraded", SEED)
        seed_lti("upgraded")

    def upgrade(self):
        before = preserved("upgraded")
        revisions = sql("upgraded", REVISIONS)
        # Fail after the Organizations DDL has run, with the exact candidate SQL.
        # Removing the test-only fault must allow ordinary Atlas retry, without
        # patching the revision ledger or accepting a partially applied schema.
        sql(
            "upgraded",
            """
          CREATE FUNCTION public.reject_runtime_fixture() RETURNS event_trigger
          LANGUAGE plpgsql AS $$ BEGIN
            IF current_query() LIKE '%CREATE TABLE aegaeon.runtime_security_budgets%' THEN
              RAISE EXCEPTION 'injected runtime table installation failure';
            END IF;
          END $$;
          CREATE EVENT TRIGGER reject_runtime_fixture ON ddl_command_start
            WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.reject_runtime_fixture();
        """,
        )
        failed = self.migrate("upgraded", self.args.migrations, succeeds=False)
        assert "injected runtime table installation failure" in failed
        assert preserved("upgraded") == before
        assert sql("upgraded", REVISIONS) == revisions
        assert sql("upgraded", "SELECT to_regclass('aegaeon.authorization_domains')")[0][0] is None
        sql(
            "upgraded",
            "DROP EVENT TRIGGER reject_runtime_fixture; "
            "DROP FUNCTION public.reject_runtime_fixture()",
        )
        self.migrate("upgraded", self.args.migrations)
        observed_revisions = dict(sql("upgraded", REVISIONS))
        assert all(observed_revisions[version] == digest for version, digest in revisions)
        assert preserved("upgraded") == before
        self.provision("upgraded")
        self.migrate("fresh", self.args.migrations)
        self.provision("fresh")
        assert connection_reader_privileges("upgraded") == connection_reader_privileges("fresh")
        assert sql("upgraded", PHYSICAL) == sql("fresh", PHYSICAL)
        assert sql("upgraded", RUNTIME_SHAPE) == sql("fresh", RUNTIME_SHAPE)
        assert sql("upgraded", PREFLIGHT) == sql("fresh", PREFLIGHT)
        return before

    def runtime_activation(self):
        # Actual product provisioning and operator SQL, without fixture-only grants.
        # The pre-PR application login already needs ordinary schema usage.
        sql("fresh", "GRANT USAGE ON SCHEMA aegaeon TO catalog_runtime")
        self.run(
            [
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-v",
                "runtime_role=catalog_runtime",
                "-v",
                "commit=true",
                "-f",
                str(self.args.runtime_provision),
            ],
            env=os.environ | {"PGDATABASE": "fresh"},
        )
        assert sql("fresh", PREFLIGHT)
        with psycopg.connect(dbname="fresh", user="catalog_runtime") as connection:
            connection.execute("SELECT * FROM aegaeon.end_user_identity_owners LIMIT 1")
            connection.execute("SELECT * FROM aegaeon.end_user_subject_reservations LIMIT 1")
            assert connection.execute("SELECT * FROM aegaeon_lifecycle.current").fetchall() == []
            assert not connection.execute(
                "SELECT has_function_privilege(current_user,"
                "'aegaeon_lifecycle.activate_v1(uuid,uuid,uuid,uuid,jsonb)','EXECUTE')"
            ).fetchone()[0]
        values = [
            "deployment_id=10000000-0000-0000-0000-000000000001",
            "previous_generation=",
            "generation=10000000-0000-0000-0000-000000000002",
            "operation_id=10000000-0000-0000-0000-000000000003",
        ]
        command = ["psql", "-X", "-v", "ON_ERROR_STOP=1"]
        for value in values:
            command += ["-v", value]
        environment = os.environ | {"PGDATABASE": "fresh", "PGUSER": "catalog_maintenance"}
        self.run([*command, "-f", str(self.args.activation)], env=environment)
        assert sql("fresh", "SELECT count(*) FROM aegaeon_lifecycle.current")[0][0] == 0
        self.run([*command, "-v", "commit=true", "-f", str(self.args.activation)], env=environment)
        assert sql("fresh", "SELECT count(*) FROM aegaeon_lifecycle.activations")[0][0] == 1
        # A lost-response retry cannot accidentally create another activation.
        self.run(
            [*command, "-v", "commit=true", "-f", str(self.args.activation)],
            env=environment,
            succeeds=False,
        )
        assert (
            sql("fresh", "SELECT actor FROM aegaeon_lifecycle.activations")[0][0]
            == "catalog_maintenance"
        )

    def predecessors(self):
        # Actual earlier checkers fail on the combined database; no simulated result.
        rejected = []
        for name in ["20261102103000_lti_admission_inventory.sql", FINAL, MANAGEMENT]:
            source = (self.args.migrations / name).read_text()
            definition = re.search(
                r"CREATE OR REPLACE FUNCTION aegaeon.subject_history_preflight\(.*?"
                r"AS \$(?P<tag>functionx?)\$.*?\$(?P=tag)\$;",
                source,
                re.DOTALL,
            ).group()
            sql("upgraded", definition)
            observed_error = None
            try:
                sql("upgraded", PREFLIGHT)
            except psycopg.errors.RaiseException as error:
                observed_error = str(error)
            if name == MANAGEMENT:
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
        assert len(rejected) == 2
        return rejected

    def schema(self):
        # Physical shape only: never invent an Atlas history for the schema artifact.
        self.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-f", str(self.args.schema)],
            env=os.environ | {"PGDATABASE": "from_schema"},
        )
        assert connection_reader_privileges("from_schema") == connection_reader_privileges("fresh")
        assert sql("from_schema", PHYSICAL) == sql("fresh", PHYSICAL)
        assert sql("from_schema", RUNTIME_SHAPE) == sql("fresh", RUNTIME_SHAPE)

    def restore(self):
        # A real logical backup must preserve the strict observed shape, data
        # and immutable revision history in a newly allocated physical database.
        dump = self.args.output / "current.dump"
        self.run(["pg_dump", "-Fc", "--file", str(dump), "upgraded"])
        sql("postgres", "CREATE DATABASE restored OWNER catalog_migration")
        self.run(["pg_restore", "--exit-on-error", "--dbname=restored", str(dump)])
        assert connection_reader_privileges("restored") == connection_reader_privileges("upgraded")
        assert sql("restored", PHYSICAL) == sql("upgraded", PHYSICAL)
        assert sql("restored", RUNTIME_SHAPE) == sql("upgraded", RUNTIME_SHAPE)
        assert sql("restored", PREFLIGHT) == sql("upgraded", PREFLIGHT)
        assert sql("restored", REVISIONS) == sql("upgraded", REVISIONS)
        assert preserved("restored") == preserved("upgraded")
        # Same identifier contract: length and control rejection may not weaken.
        expression = sql("restored", PHYSICAL)[0][0]["constraints"]
        guard = next(
            row["definition"]
            for row in expression
            if row["name"] == "application_organizations_external_id_check"
        )
        for value, permitted in [
            ("", False),
            ("a", True),
            ("a" * 256, True),
            ("a" * 257, False),
            ("組織", True),
            ("あ" * 85 + "a", True),
            ("あ" * 86, False),
            ("a\n", False),
            ("A", True),
            ("a", True),
        ]:
            with psycopg.connect(dbname="restored") as connection:
                observed = connection.execute(
                    "SELECT "  # noqa: S608 — observed fixed constraint in owned fixture
                    + guard.removeprefix("CHECK ")
                    + " FROM (SELECT %s::text AS external_id) v",
                    (value,),
                ).fetchone()[0]
                assert observed is permitted
        dump.unlink()


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
    for name in [
        "migrations",
        "schema",
        "provision",
        "management-provision",
        "management-evaluator",
        "runtime-provision",
        "activation",
        "baseline",
        "output",
    ]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    with (args.output / "operations.log").open("w") as log:
        fixture = Fixture(args, log)
        fixture.setup()
        before = fixture.upgrade()
        rejected = fixture.predecessors()
        fixture.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-f", str(args.management_evaluator)],
            env=os.environ | {"PGDATABASE": "upgraded"},
        )
        corruptions()
        assert preserved("upgraded") == before
        fixture.schema()
        fixture.restore()
        fixture.runtime_activation()
        result = {
            "main_baseline": fixture.inventory["revision"],
            "main_migrations": len(fixture.inventory["files"]),
            "final_migrations": len(list(args.migrations.glob("*.sql"))),
            "fresh_and_upgrade_catalogs_equal": True,
            "schema_physical_equal": True,
            "actual_dump_restore_catalog_data_and_revisions_equal": True,
            "external_identifier_predicate_preserved": True,
            "retained_attribute_provenance_and_identity": True,
            "retained_password_credentials": True,
            "durable_runtime_and_lifecycle_schema_equal": True,
            "linear_upgrade_preserves_old_ledger": True,
            "actual_runtime_grants_and_maintenance_activation_script": True,
            "injected_late_failure_rolls_back_and_same_source_retry_succeeds": True,
            "predecessor_checkers_rejected": rejected,
            "corruptions_rejected": CORRUPTIONS,
            "scope": "PostgreSQL catalog/migration tests; not runtime or product assurance",
        }
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
