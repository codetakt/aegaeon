use anyhow::{bail, Context, Result};
use sqlx::PgPool;

/// Check the installed client authority and the all-retained-client upgrade barrier.
///
/// # Errors
///
/// Refuses missing or altered deployment objects and unresolved legacy choices.
/// This does not protect against arbitrary privileged replacement of function bodies.
pub async fn preflight_client_dpop_minimum(pool: &PgPool) -> Result<()> {
    let shape: bool = sqlx::query_scalar(
        r"
SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_attribute a
  JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
  WHERE n.nspname = 'aegaeon' AND c.relname = 'clients' AND c.relkind = 'r'
    AND a.attname = 'dpop_bound_access_tokens' AND NOT a.attisdropped
    AND a.atttypid = 'pg_catalog.bool'::pg_catalog.regtype
    AND NOT a.attnotnull AND a.attgenerated = '' AND a.attidentity = ''
    AND pg_catalog.pg_get_expr(d.adbin, d.adrelid) = 'false'
) AND EXISTS (
  SELECT 1 FROM pg_catalog.pg_trigger t
  JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
  JOIN pg_catalog.pg_namespace function_namespace ON function_namespace.oid = p.pronamespace
  WHERE n.nspname = 'aegaeon' AND c.relname = 'clients'
    AND t.tgname = 'clients_dpop_minimum_guard' AND t.tgenabled = 'O'
    AND t.tgtype = 23 AND NOT t.tgisinternal AND t.tgconstraint = 0
    AND t.tgnargs = 0 AND t.tgqual IS NULL AND t.tgattr::text = ''
    AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
    AND function_namespace.nspname = 'aegaeon' AND p.proname = 'guard_client_dpop_minimum'
    AND p.pronargs = 0 AND p.prokind = 'f' AND NOT p.prosecdef
    AND p.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
)",
    )
    .fetch_one(pool)
    .await
    .context("Failed to inspect client DPoP requirement schema")?;
    if !shape {
        bail!("Client DPoP requirement schema is unavailable or invalid");
    }
    let unresolved: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM aegaeon.clients WHERE dpop_bound_access_tokens IS NULL)",
    )
    .fetch_one(pool)
    .await
    .context("Failed to check client DPoP requirements")?;
    if unresolved {
        bail!("Client DPoP requirements are unresolved; complete the offline upgrade");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
