use super::super::super::{
    federation_trust_chain_entry_from_row_result, management_internal_error,
};
use crate::management::types::FederationTrustChainEntry;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn store_refreshed_federation_trust_chain(
    tx: &mut Transaction<'_, Postgres>,
    trust_chain_id: Uuid,
    environment_id: Uuid,
    chain_jwts: serde_json::Value,
    ttl_secs: i64,
    request_id: &str,
) -> Result<FederationTrustChainEntry, Response> {
    let refreshed_row = sqlx::query(
        r#"
UPDATE aegaeon.federation_trust_chains
SET chain_jwts = $1,
    resolved_at = NOW(),
    expires_at = NOW() + ($2 * INTERVAL '1 second')
WHERE id = $3
  AND environment_id = $4
RETURNING
  id,
  environment_id,
  leaf_entity_id,
  anchor_entity_id,
  chain_jwts,
  to_char(resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS resolved_at,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
        "#,
    )
    .bind(chain_jwts)
    .bind(ttl_secs)
    .bind(trust_chain_id)
    .bind(environment_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        management_internal_error(request_id, "Failed to refresh federation trust chain")
    })?;

    federation_trust_chain_entry_from_row_result(&refreshed_row, request_id)
}
