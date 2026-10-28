-- Checked administrative setup. Supply existing login names with psql -v.
-- Default ROLLBACK; reviewed installation additionally uses -v commit=true.
\set ON_ERROR_STOP on
\if :{?runtime_role}
\else
  \echo 'runtime_role is required'
  \quit 3
\endif
\if :{?migration_role}
\else
  \echo 'migration_role is required'
  \quit 3
\endif
\if :{?maintenance_role}
\else
  \echo 'maintenance_role is required'
  \quit 3
\endif
\if :{?commit}
\else
  \set commit false
\endif
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SELECT pg_catalog.set_config('aegaeon.provision_runtime_role', :'runtime_role', true);
SELECT pg_catalog.set_config('aegaeon.provision_migration_role', :'migration_role', true);
SELECT pg_catalog.set_config('aegaeon.provision_maintenance_role', :'maintenance_role', true);
DO $provision$
DECLARE
  runtime_name text := pg_catalog.current_setting('aegaeon.provision_runtime_role');
  migration_name text := pg_catalog.current_setting('aegaeon.provision_migration_role');
  maintenance_name text := pg_catalog.current_setting('aegaeon.provision_maintenance_role');
  dedicated text; existing record;
BEGIN
  IF runtime_name = migration_name OR runtime_name = maintenance_name OR migration_name = maintenance_name THEN
    RAISE EXCEPTION 'runtime, migration and maintenance identities must be distinct';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = runtime_name AND rolcanlogin
      AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'runtime must be an existing restricted login; no identity is created automatically';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = migration_name AND rolcanlogin)
     OR NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = maintenance_name AND rolcanlogin
      AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'migration and restricted maintenance logins must already exist';
  END IF;
  FOREACH dedicated IN ARRAY ARRAY['aegaeon_subject_owner', 'aegaeon_subject_maintenance'] LOOP
    SELECT * INTO existing FROM pg_catalog.pg_roles WHERE rolname = dedicated;
    IF FOUND THEN
      IF existing.rolcanlogin OR existing.rolsuper OR existing.rolcreatedb OR existing.rolcreaterole
         OR existing.rolreplication OR existing.rolbypassrls THEN
        RAISE EXCEPTION 'incompatible dedicated subject role; administrator remediation required';
      END IF;
      IF EXISTS (SELECT FROM pg_catalog.pg_auth_members WHERE member = existing.oid) THEN
        RAISE EXCEPTION 'dedicated subject groups must not inherit unrelated roles';
      END IF;
    ELSE
      EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', dedicated);
    END IF;
    IF pg_catalog.pg_has_role(runtime_name, dedicated, 'MEMBER') THEN
      RAISE EXCEPTION 'runtime may not belong to subject owner or maintenance authority';
    END IF;
    IF pg_catalog.to_regnamespace('aegaeon') IS NOT NULL
       AND pg_catalog.has_schema_privilege(dedicated, 'aegaeon', 'CREATE') THEN
      RAISE EXCEPTION 'dedicated subject group has preexisting schema CREATE; no unrelated grant is silently revoked';
    END IF;
  END LOOP;
  IF pg_catalog.pg_has_role(maintenance_name, 'aegaeon_subject_owner', 'MEMBER') THEN
    RAISE EXCEPTION 'maintenance caller may not assume object ownership';
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_auth_members am JOIN pg_catalog.pg_roles r ON r.oid = am.member
             WHERE am.roleid = 'aegaeon_subject_owner'::regrole AND r.rolname <> migration_name) THEN
    RAISE EXCEPTION 'subject owner has an unexpected member; administrator review required';
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_auth_members am JOIN pg_catalog.pg_roles r ON r.oid = am.member
             WHERE am.roleid = 'aegaeon_subject_maintenance'::regrole AND r.rolname <> maintenance_name) THEN
    RAISE EXCEPTION 'subject maintenance has an unexpected member; administrator review required';
  END IF;
  EXECUTE pg_catalog.format('GRANT aegaeon_subject_owner TO %I WITH INHERIT FALSE, SET TRUE', migration_name);
  EXECUTE pg_catalog.format('GRANT aegaeon_subject_maintenance TO %I WITH INHERIT TRUE, SET TRUE', maintenance_name);
  IF pg_catalog.to_regnamespace('aegaeon') IS NOT NULL THEN
    GRANT USAGE ON SCHEMA aegaeon TO aegaeon_subject_owner, aegaeon_subject_maintenance;
  END IF;
  IF pg_catalog.to_regclass('aegaeon.subject_ownership_namespaces') IS NOT NULL THEN
    EXECUTE pg_catalog.format('GRANT SELECT ON aegaeon.subject_ownership_namespaces, aegaeon.subject_ownership_adoptions TO %I', runtime_name);
    IF EXISTS (SELECT FROM pg_catalog.pg_proc p
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
      WHERE p.oid='aegaeon.validate_subject_ownership_namespace_v1(uuid)'::regprocedure
        AND (a.grantee NOT IN ('aegaeon_subject_owner'::regrole, runtime_name::regrole)
          OR a.privilege_type<>'EXECUTE' OR (a.grantee<>'aegaeon_subject_owner'::regrole AND a.is_grantable))) THEN
      RAISE EXCEPTION 'runtime namespace entry has unrelated grants; explicit administrator review required';
    END IF;
    EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid) TO %I', runtime_name);
    EXECUTE pg_catalog.format('GRANT SELECT ON TABLE %s TO %I', aegaeon.subject_history_revision_relation(), runtime_name);
    -- Reject incompatible inherited/SET authority and every maintenance member.
    -- No incompatible existing grant is silently removed.
    PERFORM aegaeon.subject_history_preflight(runtime_name);
  END IF;
END
$provision$;
\if :commit
COMMIT;
\else
ROLLBACK;
\endif
