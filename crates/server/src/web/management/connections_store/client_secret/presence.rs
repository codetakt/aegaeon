use axum::response::Response;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::management_internal_error;

pub(in crate::web::management) async fn connection_client_secret_present(
    pool: &PgPool,
    environment_id: Uuid,
    connection_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query_scalar::<_, bool>(
        r"
SELECT client_secret_encrypted IS NOT NULL
FROM aegaeon.connections
WHERE id = $1
  AND environment_id = $2
  AND status <> 'DELETED'
        ",
    )
    .bind(connection_id)
    .bind(environment_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
    .map(|value| matches!(value, Some(true)))
}

pub(super) async fn connection_client_secret_present_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    connection_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query_scalar::<_, bool>(
        r"
SELECT client_secret_encrypted IS NOT NULL
FROM aegaeon.connections
WHERE id = $1
  AND environment_id = $2
  AND status <> 'DELETED'
        ",
    )
    .bind(connection_id)
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
    .map(|value| matches!(value, Some(true)))
}
