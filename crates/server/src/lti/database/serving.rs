//! Read-only projection of the permanent subject serving-role restrictions.
//! Keep the protected relations/helpers aligned with the adopted catalog. No
//! EXECUTE grant on a definer or private history helper is added for management.
use anyhow::{bail, Result};
use sqlx::{Postgres, Transaction};

const AUTHORITY: &str = r"
WITH reachable AS (
 SELECT r.* FROM pg_catalog.pg_roles r
 WHERE EXISTS (SELECT FROM pg_catalog.pg_roles entry
   WHERE pg_catalog.pg_has_role(session_user,entry.oid,'SET')
     AND pg_catalog.pg_has_role(entry.oid,r.oid,'USAGE'))
), guarded AS (
 SELECT c.oid,c.relowner,c.relname FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE (n.nspname='aegaeon' AND c.relname IN
   ('environments','end_users','subject_ownership_namespaces','subject_ownership_adoptions',
    'end_user_identity_owners','end_user_subject_reservations','user_attribute_sources',
    'lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents'))
 OR (c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon'))
), audit AS (
 SELECT c.oid,c.relowner FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass) t
 JOIN pg_catalog.pg_class c ON c.oid=t.relid
), trigger_functions AS (
 SELECT p.proowner FROM pg_catalog.pg_trigger t
 JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
 WHERE t.tgrelid IN (SELECT oid FROM guarded UNION SELECT oid FROM audit)
)
";

const WRITER: &str = r"
SELECT current_user=session_user
 AND pg_catalog.current_setting('session_replication_role')='origin'
 AND EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname=session_user AND rolcanlogin)
 AND NOT EXISTS (SELECT FROM reachable r WHERE
   r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
   OR r.rolname IN ('aegaeon_subject_owner','aegaeon_subject_maintenance')
   OR pg_catalog.has_parameter_privilege(r.oid,'session_replication_role','SET')
   OR pg_catalog.has_schema_privilege(r.oid,'aegaeon','CREATE')
   OR EXISTS(SELECT FROM pg_catalog.pg_namespace n WHERE n.nspname='aegaeon' AND n.nspowner=r.oid)
   OR EXISTS(SELECT FROM trigger_functions f WHERE f.proowner=r.oid)
   OR EXISTS(SELECT FROM guarded g WHERE g.relowner=r.oid
     OR pg_catalog.has_table_privilege(r.oid,g.oid,'TRIGGER')
     OR (g.relname NOT IN ('environments','end_users','user_attribute_sources',
          'lti_registrations','lti_registration_revisions','lti_identifiers','lti_launch_intents')
       AND (pg_catalog.has_table_privilege(r.oid,g.oid,'INSERT,UPDATE,DELETE,TRUNCATE')
         OR pg_catalog.has_any_column_privilege(r.oid,g.oid,'INSERT,UPDATE'))))
   OR EXISTS(SELECT FROM audit a WHERE a.relowner=r.oid
     OR pg_catalog.has_table_privilege(r.oid,a.oid,'UPDATE,DELETE,TRUNCATE,TRIGGER')
     OR pg_catalog.has_any_column_privilege(r.oid,a.oid,'UPDATE'))
   OR EXISTS(SELECT FROM pg_catalog.pg_proc p
     JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='aegaeon' AND
       (p.proname LIKE 'subject_history_%' OR p.proname IN
        ('subject_ownership_guard_user','subject_ownership_guard_environment',
         'subject_ownership_immutable','subject_ownership_guard_insert',
         'inventory_subject_ownership_history_v1','adopt_subject_ownership_history_v1',
         'validate_subject_ownership_namespace_v1'))
       AND (p.proowner=r.oid OR pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE'))))
";

pub(super) async fn require_protected_trigger_owners(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    let sql = format!(
        "{AUTHORITY} SELECT NOT EXISTS(SELECT FROM reachable r
         JOIN trigger_functions f ON f.proowner=r.oid)"
    );
    if !sqlx::query_scalar::<_, bool>(&sql)
        .fetch_one(&mut **tx)
        .await?
    {
        bail!("LTI serving database principal can own a protected trigger function");
    }
    Ok(())
}

pub(super) async fn require_protected_writer(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    let sql = format!("{AUTHORITY} {WRITER}");
    if !sqlx::query_scalar::<_, bool>(&sql)
        .fetch_one(&mut **tx)
        .await?
    {
        bail!("LTI management database principal can bypass protected identity or audit authority");
    }
    Ok(())
}
