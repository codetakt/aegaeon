//! Attribute-source authority for the two serving database principals.
use anyhow::{bail, Context, Result};
use sqlx::{PgPool, Postgres, Row, Transaction};

mod serving;

/// Serving credentials never administer role memberships. ADMIN OPTION can
/// grant SET/INHERIT access even when both options are currently false. Use
/// PostgreSQL's own administrative-membership predicate, including indirect
/// memberships, instead of treating today's effective permissions as a ceiling.
/// Host file/program roles can bypass database ACLs and are also forbidden.
async fn require_restricted_role_authority(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    let administrative: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM pg_catalog.pg_roles r
         WHERE pg_catalog.pg_has_role(session_user,r.oid,'MEMBER WITH ADMIN OPTION')
           OR (r.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')
             AND EXISTS(SELECT FROM pg_catalog.pg_roles entry
               WHERE pg_catalog.pg_has_role(session_user,entry.oid,'SET')
                 AND pg_catalog.pg_has_role(entry.oid,r.oid,'USAGE'))))",
    )
    .fetch_one(&mut **tx)
    .await?;
    if administrative {
        bail!("LTI serving database principals must not administer role memberships or access server files/programs");
    }
    Ok(())
}

const READER: &str = r"
SELECT current_user = session_user
 AND pg_catalog.has_table_privilege(current_user,'aegaeon.user_attribute_sources','SELECT')
 AND NOT EXISTS (
   SELECT FROM pg_catalog.pg_roles r
   WHERE EXISTS (SELECT FROM pg_catalog.pg_roles entry
     WHERE pg_catalog.pg_has_role(session_user,entry.oid,'SET')
       AND pg_catalog.pg_has_role(entry.oid,r.oid,'USAGE'))
     AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
       OR pg_catalog.has_schema_privilege(r.oid,'aegaeon','CREATE')
       OR pg_catalog.has_table_privilege(r.oid,'aegaeon.user_attribute_sources',
            'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
       OR pg_catalog.has_any_column_privilege(r.oid,'aegaeon.user_attribute_sources','INSERT,UPDATE')
       OR r.oid=(SELECT relowner FROM pg_catalog.pg_class
                  WHERE oid='aegaeon.user_attribute_sources'::regclass)))
";

/// Evaluate the actual transaction's effective and SET-reachable authority.
pub(crate) async fn require_reader(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    require_restricted_role_authority(tx).await?;
    serving::require_protected_trigger_owners(tx).await?;
    if !sqlx::query_scalar::<_, bool>(READER)
        .fetch_one(&mut **tx)
        .await?
    {
        bail!("LTI requires a restricted attribute-read database principal");
    }
    Ok(())
}

async fn actor(tx: &mut Transaction<'_, Postgres>) -> Result<(String, String, i64)> {
    let row = sqlx::query(
        "SELECT current_user::text AS actor, current_database()::text AS database,
         (SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname=current_database()) AS oid",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok((
        row.try_get("actor")?,
        row.try_get("database")?,
        row.try_get("oid")?,
    ))
}

async fn require_writer(tx: &mut Transaction<'_, Postgres>, reader: &str) -> Result<()> {
    require_restricted_role_authority(tx).await?;
    let allowed: bool = sqlx::query_scalar(
        "SELECT current_user = session_user AND current_user::text <> $1
         AND pg_catalog.has_table_privilege(current_user,'aegaeon.user_attribute_sources','SELECT')
         AND pg_catalog.has_table_privilege(current_user,'aegaeon.user_attribute_sources','INSERT')
         AND pg_catalog.has_table_privilege(current_user,'aegaeon.user_attribute_sources','UPDATE')
         AND NOT pg_catalog.pg_has_role($1::name,current_user,'USAGE')
         AND NOT pg_catalog.pg_has_role($1::name,current_user,'SET')
         AND NOT EXISTS (SELECT FROM pg_catalog.pg_roles r
           WHERE EXISTS (SELECT FROM pg_catalog.pg_roles entry
             WHERE pg_catalog.pg_has_role(session_user,entry.oid,'SET')
               AND pg_catalog.pg_has_role(entry.oid,r.oid,'USAGE'))
           AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
             OR pg_catalog.has_schema_privilege(r.oid,'aegaeon','CREATE')
             OR pg_catalog.pg_has_role(r.oid,
                (SELECT relowner FROM pg_catalog.pg_class WHERE oid='aegaeon.user_attribute_sources'::regclass),'USAGE')
             OR pg_catalog.pg_has_role(r.oid,
                (SELECT relowner FROM pg_catalog.pg_class WHERE oid='aegaeon.user_attribute_sources'::regclass),'SET')))",
    )
    .bind(reader)
    .fetch_one(&mut **tx)
    .await?;
    if !allowed {
        bail!("LTI requires a distinct restricted attribute-write database principal");
    }
    serving::require_protected_writer(tx).await
}

/// Validate distinct principals on the same live database. A random transaction
/// lock checks actual lock-domain identity, rather than trusting matching URLs or
/// cloned database names/IDs. Pool reconnection and restoration retain the
/// documented stable-database supplier contract.
pub(crate) async fn validate_pools(runtime: &PgPool, management: &PgPool) -> Result<()> {
    let mut read = runtime.begin().await?;
    let mut write = management.begin().await?;
    require_reader(&mut read).await?;
    let (reader, database, oid) = actor(&mut read).await?;
    let (_, writer_database, writer_oid) = actor(&mut write).await?;
    if database != writer_database || oid != writer_oid {
        bail!("runtime and management database identities differ");
    }
    require_writer(&mut write, &reader).await?;
    let nonce = uuid::Uuid::new_v4();
    let bytes = nonce.as_bytes();
    let first = i32::from_be_bytes(bytes[..4].try_into().context("lock key")?);
    let second = i32::from_be_bytes(bytes[4..8].try_into().context("lock key")?);
    let acquired: bool = sqlx::query_scalar("SELECT pg_catalog.pg_try_advisory_xact_lock($1,$2)")
        .bind(first)
        .bind(second)
        .fetch_one(&mut *read)
        .await?;
    if !acquired {
        bail!("database identity challenge is unavailable");
    }
    let other: bool = sqlx::query_scalar("SELECT pg_catalog.pg_try_advisory_xact_lock($1,$2)")
        .bind(first)
        .bind(second)
        .fetch_one(&mut *write)
        .await?;
    if other {
        bail!("management connection is outside the runtime database lock domain");
    }
    write.rollback().await?;
    read.rollback().await?;
    Ok(())
}
