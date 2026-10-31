//! Exact separately installed catalog and least-privilege boundary.
use super::{Error, Result, Role};
use sqlx::PgConnection;

const QUERY: &str = include_str!("../../../../../db/organization-witness/catalog-v1.sql");
const EXPECTED: &str = include_str!("../../../../../db/organization-witness/catalog-v2.json");

pub(super) async fn verify(connection: &mut PgConnection, role: Role) -> Result<()> {
    // Pending work must not be acknowledged under an asynchronous commit or
    // a stale/read-only supplier. Deployment durability is still a separate
    // qualification; these are necessary live configuration checks.
    let durable: bool = sqlx::query_scalar("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on' AND current_setting('synchronous_commit')='on' AND current_setting('transaction_isolation')='read committed' AND current_setting('transaction_read_only')='off'")
        .fetch_one(&mut *connection).await?;
    if !durable {
        return Err(Error::Refused);
    }
    let group = match role {
        Role::Runtime => "aegaeon_organization_witness_runtime",
        Role::Maintenance => "aegaeon_organization_witness_maintenance",
    };
    let other = match role {
        Role::Runtime => "aegaeon_organization_witness_maintenance",
        Role::Maintenance => "aegaeon_organization_witness_runtime",
    };
    let safe: bool = sqlx::query_scalar("SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AND pg_has_role(session_user,$1,'USAGE') AND NOT pg_has_role(session_user,$2,'MEMBER') AND NOT pg_has_role(session_user,'aegaeon_organization_witness_owner','MEMBER') AND NOT EXISTS(SELECT FROM pg_roles privileged WHERE (privileged.rolsuper OR privileged.rolcreatedb OR privileged.rolcreaterole OR privileged.rolreplication OR privileged.rolbypassrls) AND pg_has_role(session_user,privileged.oid,'MEMBER')) AND NOT EXISTS(SELECT FROM pg_database d WHERE d.datname=current_database() AND pg_has_role(session_user,d.datdba,'MEMBER')) AND session_user=current_user FROM pg_roles WHERE rolname=session_user")
        .bind(group).bind(other).fetch_one(&mut *connection).await?;
    if !safe {
        return Err(Error::Refused);
    }
    let writable: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='organization_witness' AND c.relkind IN ('r','p') AND (has_table_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))")
        .fetch_one(&mut *connection).await?;
    let actual: serde_json::Value = sqlx::query_scalar(QUERY)
        .fetch_one(&mut *connection)
        .await?;
    let expected: serde_json::Value = serde_json::from_str(EXPECTED)?;
    if writable || actual != expected {
        return Err(Error::Refused);
    }
    Ok(())
}
