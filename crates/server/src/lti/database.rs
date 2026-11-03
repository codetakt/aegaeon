//! Attribute-source authority for the two serving database principals.
use anyhow::{bail, Context, Result};
use sqlx::{PgPool, Postgres, Row, Transaction};

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
    Ok(())
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
