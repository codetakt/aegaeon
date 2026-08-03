use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::FederationEntityCacheEntry;

use super::super::super::required_row_value;

fn federation_entity_cache_entry_from_row(
    row: &PgRow,
    request_id: &str,
) -> Result<FederationEntityCacheEntry, Response> {
    let message = "Failed to load federation entity cache entry";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let entity_id: String = required_row_value(row, "entity_id", request_id, message)?;
    let entity_configuration_jws: String =
        required_row_value(row, "entity_configuration_jws", request_id, message)?;
    let parsed_statement: serde_json::Value =
        required_row_value(row, "parsed_statement", request_id, message)?;
    let fetched_at: String = required_row_value(row, "fetched_at", request_id, message)?;
    let expires_at: String = required_row_value(row, "expires_at", request_id, message)?;
    Ok(FederationEntityCacheEntry {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        entity_id,
        entity_configuration_jws,
        parsed_statement,
        fetched_at,
        expires_at,
    })
}

pub(in crate::web::management) fn federation_entity_cache_entry_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<FederationEntityCacheEntry, Response> {
    federation_entity_cache_entry_from_row(row, request_id)
}
