use super::super::super::{
    federation_trust_chain_entry_from_row_result, management_internal_error,
};
use super::super::errors::federation_trust_chain_not_found;
use crate::management::types::FederationTrustChainEntry;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn load_federation_trust_chain_entry(
    tx: &mut Transaction<'_, Postgres>,
    trust_chain_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<FederationTrustChainEntry, Response> {
    let existing_row = sqlx::query(
        r#"
SELECT
  id,
  environment_id,
  leaf_entity_id,
  anchor_entity_id,
  chain_jwts,
  to_char(resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS resolved_at,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
FROM aegaeon.federation_trust_chains
WHERE id = $1
  AND environment_id = $2
        "#,
    )
    .bind(trust_chain_id)
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to load federation trust chain"))?;

    let Some(existing_row) = existing_row else {
        return Err(federation_trust_chain_not_found(request_id));
    };

    federation_trust_chain_entry_from_row_result(&existing_row, request_id)
}
