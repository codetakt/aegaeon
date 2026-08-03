use super::status::{configured_status_from_row, unconfigured_status};
use crate::management::types::DcrBearerTokenStatus;
use crate::web::management::management_internal_error;
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(in crate::web::management) async fn load_dcr_bearer_token_status(
    pool: &PgPool,
    environment_id: Uuid,
    request_id: &str,
) -> Result<DcrBearerTokenStatus, Response> {
    let row = sqlx::query(
        r#"
SELECT
  token_hash_algorithm,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.environment_dcr_bearer_tokens
WHERE environment_id = $1
        "#,
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    row.as_ref().map_or_else(
        || Ok(unconfigured_status(environment_id)),
        |row| configured_status_from_row(environment_id, row, request_id),
    )
}
