use crate::management::types::DcrBearerTokenStatus;
use crate::web::management::required_row_value;
use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

pub(super) fn configured_status_from_row(
    environment_id: Uuid,
    row: &PgRow,
    request_id: &str,
) -> Result<DcrBearerTokenStatus, Response> {
    let hash_algorithm = required_row_value::<String>(
        row,
        "token_hash_algorithm",
        request_id,
        "DCR bearer token row is corrupted",
    )?;
    let updated_at = required_row_value::<String>(
        row,
        "updated_at",
        request_id,
        "DCR bearer token row is corrupted",
    )?;
    Ok(DcrBearerTokenStatus {
        environment_id: environment_id.to_string(),
        configured: true,
        hash_algorithm: Some(hash_algorithm),
        updated_at: Some(updated_at),
    })
}

pub(super) fn unconfigured_status(environment_id: Uuid) -> DcrBearerTokenStatus {
    DcrBearerTokenStatus {
        environment_id: environment_id.to_string(),
        configured: false,
        hash_algorithm: None,
        updated_at: None,
    }
}
