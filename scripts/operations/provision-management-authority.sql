-- Explicit installation grant administration. The three existing login identities
-- are separate; the serving role never receives bootstrap membership or table DML.
-- Run before migrations to provision roles, then after migrations to bind this
-- selected database and grant the two reviewed entrypoints. Default: ROLLBACK.
\set ON_ERROR_STOP on
\if :{?serving_role}
\else
  \echo 'serving_role is required'
  \quit 3
\endif
\if :{?migration_role}
\else
  \echo 'migration_role is required'
  \quit 3
\endif
\if :{?bootstrap_role}
\else
  \echo 'bootstrap_role is required'
  \quit 3
\endif
\if :{?commit}
\else
  \set commit false
\endif

BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SELECT pg_catalog.set_config('aegaeon.management_provision_serving', :'serving_role', true);
SELECT pg_catalog.set_config('aegaeon.management_provision_migration', :'migration_role', true);
SELECT pg_catalog.set_config('aegaeon.management_provision_bootstrap', :'bootstrap_role', true);
DO $provision$
DECLARE
  serving_name text := pg_catalog.current_setting('aegaeon.management_provision_serving');
  migration_name text := pg_catalog.current_setting('aegaeon.management_provision_migration');
  bootstrap_name text := pg_catalog.current_setting('aegaeon.management_provision_bootstrap');
  dedicated text;
  profile record;
  entry regprocedure;
  administrator_ids oid[];
BEGIN
  IF serving_name=migration_name OR serving_name=bootstrap_name OR migration_name=bootstrap_name THEN
    RAISE EXCEPTION 'serving, migration and bootstrap identities must be distinct';
  END IF;
  FOREACH dedicated IN ARRAY ARRAY[serving_name,bootstrap_name] LOOP
    IF NOT EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname=dedicated AND rolcanlogin
      AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
      RAISE EXCEPTION 'serving and bootstrap identities must be existing restricted logins';
    END IF;
    IF EXISTS(SELECT FROM pg_catalog.pg_roles privileged
      WHERE (privileged.rolsuper OR privileged.rolcreatedb OR privileged.rolcreaterole
             OR privileged.rolreplication OR privileged.rolbypassrls)
        AND pg_catalog.pg_has_role(dedicated,privileged.oid,'MEMBER'))
      OR EXISTS(SELECT FROM pg_catalog.pg_database
        WHERE datname=current_database() AND pg_catalog.pg_has_role(dedicated,datdba,'MEMBER')) THEN
      RAISE EXCEPTION 'serving and bootstrap identities must not inherit database administration';
    END IF;
  END LOOP;
  IF NOT EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname=migration_name AND rolcanlogin) THEN
    RAISE EXCEPTION 'migration identity must be an existing login';
  END IF;
  FOREACH dedicated IN ARRAY ARRAY['aegaeon_management_authority_owner','aegaeon_management_bootstrap'] LOOP
    SELECT * INTO profile FROM pg_catalog.pg_roles WHERE rolname=dedicated;
    IF FOUND THEN
      IF profile.rolcanlogin OR profile.rolsuper OR profile.rolcreatedb OR profile.rolcreaterole
        OR profile.rolreplication OR profile.rolbypassrls
        OR EXISTS(SELECT FROM pg_catalog.pg_auth_members WHERE member=profile.oid) THEN
        RAISE EXCEPTION 'incompatible management authority group; explicit administrator remediation required';
      END IF;
    ELSE
      EXECUTE pg_catalog.format(
        'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',dedicated);
    END IF;
    IF pg_catalog.pg_has_role(serving_name,dedicated,'MEMBER') THEN
      RAISE EXCEPTION 'serving identity may not hold owner or bootstrap authority';
    END IF;
  END LOOP;
  IF pg_catalog.pg_has_role(bootstrap_name,'aegaeon_management_authority_owner','MEMBER') THEN
    RAISE EXCEPTION 'bootstrap identity may not assume management authority ownership';
  END IF;
  -- A non-superuser creator receives a bootstrap-superuser ADMIN-only grant.
  -- Require that capability on BOTH protected groups, with the same grantor.
  -- This recognizes administrative capability, not grant creation history;
  -- later self-granted INHERIT/SET rows do not replace these checked grants.
  SELECT COALESCE(pg_catalog.array_agg(o.member),ARRAY[]::oid[]) INTO administrator_ids
    FROM pg_catalog.pg_auth_members o
    JOIN pg_catalog.pg_auth_members b ON b.member=o.member AND b.grantor=o.grantor
    JOIN pg_catalog.pg_roles grantor ON grantor.oid=o.grantor AND grantor.rolsuper
    WHERE o.roleid='aegaeon_management_authority_owner'::regrole
      AND b.roleid='aegaeon_management_bootstrap'::regrole
      AND o.admin_option AND NOT o.inherit_option AND NOT o.set_option
      AND b.admin_option AND NOT b.inherit_option AND NOT b.set_option;
  FOREACH dedicated IN ARRAY ARRAY['aegaeon_management_authority_owner','aegaeon_management_bootstrap'] LOOP
    -- UNION bounds cycles/duplicate grant paths. Even ADMIN-only or currently
    -- non-inheritable members need explicit approval; do not silently revoke.
    IF EXISTS(WITH RECURSIVE members(oid) AS (
        -- Include the intended grantee before its first GRANT creates a path.
        SELECT (CASE dedicated WHEN 'aegaeon_management_authority_owner' THEN migration_name ELSE bootstrap_name END)::regrole::oid
        UNION
        SELECT member FROM pg_catalog.pg_auth_members WHERE roleid=dedicated::regrole
        UNION
        SELECT am.member FROM pg_catalog.pg_auth_members am JOIN members m ON am.roleid=m.oid
      ) SELECT FROM members m JOIN pg_catalog.pg_roles r ON r.oid=m.oid
      WHERE r.rolname<>CASE dedicated WHEN 'aegaeon_management_authority_owner' THEN migration_name ELSE bootstrap_name END
        AND NOT (m.oid=ANY(administrator_ids))) THEN
      RAISE EXCEPTION 'management authority group has an unexpected member; explicit administrator remediation required';
    END IF;
  END LOOP;
  EXECUTE pg_catalog.format('GRANT aegaeon_management_authority_owner TO %I WITH INHERIT FALSE, SET TRUE',migration_name);
  EXECUTE pg_catalog.format('GRANT aegaeon_management_bootstrap TO %I WITH INHERIT TRUE, SET TRUE',bootstrap_name);

  -- An existing role creator's ADMIN capability can administer its own group;
  -- ordinary runtime/bootstrap identities were rejected above and gain none.
  IF current_user::regrole::oid=ANY(administrator_ids) THEN
    GRANT aegaeon_management_authority_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  END IF;

  IF pg_catalog.to_regnamespace('management_authority') IS NOT NULL THEN
    IF pg_catalog.to_regprocedure('management_authority.bootstrap_v1(jsonb)') IS NULL
      OR pg_catalog.to_regprocedure('management_authority.inventory_v1(jsonb)') IS NULL THEN
      RAISE EXCEPTION 'complete management authority migration is required';
    END IF;
    FOREACH entry IN ARRAY ARRAY[
      'management_authority.bootstrap_v1(jsonb)'::regprocedure,
      'management_authority.inventory_v1(jsonb)'::regprocedure] LOOP
      IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc WHERE oid=entry
          AND proowner='aegaeon_management_authority_owner'::regrole AND prosecdef) THEN
        RAISE EXCEPTION 'management authority entrypoint owner or security mode mismatch';
      END IF;
    END LOOP;
    EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA management_authority TO %I',serving_name);
    GRANT USAGE ON SCHEMA management_authority TO aegaeon_management_bootstrap;
    EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION management_authority.inventory_v1(jsonb) TO %I',serving_name);
    GRANT EXECUTE ON FUNCTION management_authority.bootstrap_v1(jsonb) TO aegaeon_management_bootstrap;
    EXECUTE pg_catalog.format(
      'INSERT INTO management_authority.bootstrap_credentials(installation_id,role_oid,role_name)
       SELECT id,%L::regrole::oid,%L::name FROM management_authority.installation
       ON CONFLICT(installation_id,role_oid) DO NOTHING',bootstrap_name,bootstrap_name);
    PERFORM management_authority.check_serving_role_v1(serving_name);
  END IF;
END
$provision$;
\if :commit
COMMIT;
\else
ROLLBACK;
\endif
