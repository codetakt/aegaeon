use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::federation::StoredTrustAnchor;
use crate::management::types::FederationTrustAnchor;

use super::super::super::required_row_value;

fn trust_anchor_from_row(row: &PgRow, request_id: &str) -> Result<FederationTrustAnchor, Response> {
    let message = "Failed to load trust anchor";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let entity_id: String = required_row_value(row, "entity_id", request_id, message)?;
    let jwks: serde_json::Value = required_row_value(row, "jwks", request_id, message)?;
    let metadata_policy: Option<serde_json::Value> =
        required_row_value(row, "metadata_policy", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let updated_at: String = required_row_value(row, "updated_at", request_id, message)?;
    Ok(FederationTrustAnchor {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        entity_id,
        jwks,
        metadata_policy,
        created_at,
        updated_at,
    })
}

pub(in crate::web::management) fn trust_anchor_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<FederationTrustAnchor, Response> {
    trust_anchor_from_row(row, request_id)
}

fn stored_trust_anchor_from_row(
    row: &PgRow,
    request_id: &str,
) -> Result<StoredTrustAnchor, Response> {
    let message = "Failed to load stored federation trust anchor";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let entity_id: String = required_row_value(row, "entity_id", request_id, message)?;
    let jwks: serde_json::Value = required_row_value(row, "jwks", request_id, message)?;
    let metadata_policy: Option<serde_json::Value> =
        required_row_value(row, "metadata_policy", request_id, message)?;
    let created_epoch: i64 = required_row_value(row, "created_epoch", request_id, message)?;
    let updated_epoch: i64 = required_row_value(row, "updated_epoch", request_id, message)?;
    Ok(StoredTrustAnchor {
        id,
        environment_id,
        entity_id,
        jwks,
        metadata_policy,
        created_at: created_epoch,
        updated_at: updated_epoch,
    })
}

pub(in crate::web::management) fn stored_trust_anchor_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<StoredTrustAnchor, Response> {
    stored_trust_anchor_from_row(row, request_id)
}
