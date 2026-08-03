use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::FederationTrustChainEntry;

use super::super::super::required_row_value;

fn federation_trust_chain_entry_from_row(
    row: &PgRow,
    request_id: &str,
) -> Result<FederationTrustChainEntry, Response> {
    let message = "Failed to load federation trust chain";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let leaf_entity_id: String = required_row_value(row, "leaf_entity_id", request_id, message)?;
    let anchor_entity_id: String =
        required_row_value(row, "anchor_entity_id", request_id, message)?;
    let chain_jwts: serde_json::Value = required_row_value(row, "chain_jwts", request_id, message)?;
    let resolved_at: String = required_row_value(row, "resolved_at", request_id, message)?;
    let expires_at: String = required_row_value(row, "expires_at", request_id, message)?;
    Ok(FederationTrustChainEntry {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        leaf_entity_id,
        anchor_entity_id,
        chain_jwts,
        resolved_at,
        expires_at,
    })
}

pub(in crate::web::management) fn federation_trust_chain_entry_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<FederationTrustChainEntry, Response> {
    federation_trust_chain_entry_from_row(row, request_id)
}
