//! Independent reference closure over validated retained source rows.
use super::{PreparationError, Result};
use sqlx::{Postgres, Transaction};

const REFERENCES: &str = r#"WITH refs AS (
  SELECT data->>'end_user_id' AS id FROM pg_temp.organization_import_rows WHERE section='memberships'
  UNION SELECT data->>'target_user_id' FROM pg_temp.organization_import_rows WHERE section='identity_requests'
  UNION SELECT data->'result'->>'userId' FROM pg_temp.organization_import_rows WHERE section='identity_requests'
  UNION SELECT data->'recipient_binding'->'binding'->>'user_id' FROM pg_temp.organization_import_rows WHERE section='challenges'
  UNION SELECT data->>'user_id' FROM pg_temp.organization_import_rows WHERE section='administrative_grants'
  UNION SELECT e->>'userId' FROM pg_temp.organization_import_rows r CROSS JOIN LATERAL jsonb_array_elements(r.data->'support_policy'->'entitlements') e WHERE r.section='domain'
  UNION SELECT data->'authority'->'actor'->>'id' FROM pg_temp.organization_import_rows WHERE section='invitations' AND data->'authority'->'actor'->>'kind'='member'
  UNION SELECT data->>'actor_id' FROM pg_temp.organization_import_rows WHERE section IN ('audit','receipts') AND data->>'actor_kind'='member'
), wanted AS (SELECT id FROM refs WHERE id IS NOT NULL), owners AS (
  SELECT row_key AS id FROM pg_temp.organization_import_rows WHERE section='owners'
) SELECT NOT EXISTS((SELECT id FROM wanted EXCEPT SELECT id FROM owners)
                   UNION ALL (SELECT id FROM owners EXCEPT SELECT id FROM wanted))"#;

pub(super) async fn check(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    let matches: bool = sqlx::query_scalar(REFERENCES)
        .fetch_one(&mut **tx)
        .await
        .map_err(PreparationError::Storage)?;
    if !matches {
        return Err(PreparationError::Invalid(
            "retained owner reference set differs from source history",
        ));
    }
    Ok(())
}
