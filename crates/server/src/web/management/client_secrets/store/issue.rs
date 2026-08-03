use super::super::super::{client_secret_from_row_result, error_response};
use crate::management::types::ClientSecret;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management::client_secrets) async fn insert_client_secret_row(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    client_id: Uuid,
    configuration_version_id: Uuid,
    secret_hash: &str,
    expires_in_days: i32,
    request_id: &str,
) -> Result<ClientSecret, Response> {
    let row = sqlx::query(
        r#"
INSERT INTO aegaeon.client_secrets (
  environment_id, client_id, configuration_version_id,
  secret_hash, secret_hash_algorithm,
  expires_at
)
VALUES ($1, $2, $3, $4, 'argon2id', now() + make_interval(days => $5))
RETURNING
  id, client_id,
  status::text AS status,
  active_slot,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
        "#,
    )
    .bind(environment_id)
    .bind(client_id)
    .bind(configuration_version_id)
    .bind(secret_hash)
    .bind(expires_in_days)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to create client secret",
            None,
            Some(request_id),
        )
    })?;

    client_secret_from_row_result(&row, request_id)
}
