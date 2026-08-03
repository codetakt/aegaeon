use super::super::super::{
    federation_entity_cache_entry_from_row_result, management_internal_error,
};
use super::super::errors::federation_entity_cache_not_found;
use crate::management::types::FederationEntityCacheEntry;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn load_federation_entity_cache_entry(
    tx: &mut Transaction<'_, Postgres>,
    entity_cache_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<FederationEntityCacheEntry, Response> {
    let existing_row = sqlx::query(
        r#"
SELECT
  id,
  environment_id,
  entity_id,
  entity_configuration_jws,
  parsed_statement,
  to_char(fetched_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS fetched_at,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
FROM aegaeon.federation_entity_cache
WHERE id = $1
  AND environment_id = $2
        "#,
    )
    .bind(entity_cache_id)
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| {
        management_internal_error(request_id, "Failed to load federation entity cache entry")
    })?;

    let Some(existing_row) = existing_row else {
        return Err(federation_entity_cache_not_found(request_id));
    };

    federation_entity_cache_entry_from_row_result(&existing_row, request_id)
}
