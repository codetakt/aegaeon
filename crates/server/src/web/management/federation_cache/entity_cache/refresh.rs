use super::super::super::{
    federation_entity_cache_entry_from_row_result, management_internal_error,
};
use crate::management::types::FederationEntityCacheEntry;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn store_refreshed_federation_entity_cache_entry(
    tx: &mut Transaction<'_, Postgres>,
    entity_cache_id: Uuid,
    environment_id: Uuid,
    jws: &str,
    parsed_statement: serde_json::Value,
    ttl_secs: i64,
    request_id: &str,
) -> Result<FederationEntityCacheEntry, Response> {
    let refreshed_row = sqlx::query(
        r#"
UPDATE aegaeon.federation_entity_cache
SET entity_configuration_jws = $1,
    parsed_statement = $2,
    fetched_at = NOW(),
    expires_at = NOW() + ($3 * INTERVAL '1 second')
WHERE id = $4
  AND environment_id = $5
RETURNING
  id,
  environment_id,
  entity_id,
  entity_configuration_jws,
  parsed_statement,
  to_char(fetched_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS fetched_at,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
        "#,
    )
    .bind(jws)
    .bind(parsed_statement)
    .bind(ttl_secs)
    .bind(entity_cache_id)
    .bind(environment_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        management_internal_error(
            request_id,
            "Failed to refresh federation entity cache entry",
        )
    })?;

    federation_entity_cache_entry_from_row_result(&refreshed_row, request_id)
}
