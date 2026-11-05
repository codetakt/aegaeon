use crate::web::management::http_errors::management_database_error as database_error;
use crate::web::management::request_support::owned;
use axum::response::Response;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn connection_client_secret_present(
    pool: &PgPool,
    environment_id: Uuid,
    connection_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    {
        let mut connection = owned::connection(pool)
            .await
            .map_err(|_| owned::unavailable(request_id))?;
        let result = sqlx::query_scalar::<_, bool>(
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
        .fetch_optional(
            connection
                .as_mut()
                .map_err(|_| owned::unavailable(request_id))?,
        )
        .await;
        connection.release().await;
        owned::scoped().map_err(|_| owned::unavailable(request_id))?;
        result
    }
    .map_err(|error| database_error(request_id, &error, "Database query failed"))
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
    .map_err(|error| database_error(request_id, &error, "Database query failed"))
    .map(|value| matches!(value, Some(true)))
}
