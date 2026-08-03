use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::{ApiKey, ApiKeyCapability};
use crate::web::management::required_row_value;

fn api_key_from_row(row: &PgRow, request_id: &str) -> Result<ApiKey, Response> {
    let message = "Failed to load API key";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let team_id: Uuid = required_row_value(row, "team_id", request_id, message)?;
    let name: String = required_row_value(row, "name", request_id, message)?;
    let key_prefix: String = required_row_value(row, "key_prefix", request_id, message)?;
    let capabilities: Vec<String> = required_row_value(row, "capabilities", request_id, message)?;
    let status: String = required_row_value(row, "status", request_id, message)?;
    let expires_at: Option<String> = required_row_value(row, "expires_at", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let capabilities = capabilities
        .iter()
        .map(String::as_str)
        .map(ApiKeyCapability::from_db_value)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            crate::web::management::management_internal_error(
                request_id,
                "Failed to load API key capabilities",
            )
        })?;

    Ok(ApiKey {
        id: id.to_string(),
        team_id: team_id.to_string(),
        name,
        key_prefix,
        capabilities,
        status,
        expires_at,
        created_at,
    })
}

pub(in crate::web::management::api_keys) fn api_key_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<ApiKey, Response> {
    api_key_from_row(row, request_id)
}
