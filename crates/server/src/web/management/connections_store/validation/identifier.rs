use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;
use uuid::Uuid;

use super::super::super::{error_response, management_internal_error};

pub(in crate::web::management) async fn ensure_connection_identifier_available(
    pool: &PgPool,
    environment_id: Uuid,
    connection_identifier: &str,
    excluded_connection_id: Option<Uuid>,
    request_id: &str,
) -> Result<(), Response> {
    let mut query = sqlx::query(
        r"
SELECT id
FROM aegaeon.connections
WHERE environment_id = $1
  AND connection_identifier = $2
  AND status <> 'DELETED'
        ",
    )
    .bind(environment_id)
    .bind(connection_identifier);

    let conflict_row = if let Some(connection_id) = excluded_connection_id {
        query = sqlx::query(
            r"
SELECT id
FROM aegaeon.connections
WHERE environment_id = $1
  AND connection_identifier = $2
  AND status <> 'DELETED'
  AND id <> $3
LIMIT 1
            ",
        )
        .bind(environment_id)
        .bind(connection_identifier)
        .bind(connection_id);
        query
            .fetch_optional(pool)
            .await
            .map_err(|_| management_internal_error(request_id, "Database query failed"))?
    } else {
        query
            .fetch_optional(pool)
            .await
            .map_err(|_| management_internal_error(request_id, "Database query failed"))?
    };

    if conflict_row.is_some() {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "connectionIdentifier already exists",
            None,
            Some(request_id),
        ));
    }

    Ok(())
}
