use axum::{http::StatusCode, response::Response};
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::client_input::ClientInput;
use super::super::super::error_response;

pub(in crate::web::management) async fn insert_client_row(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    input: &ClientInput,
    request_id: &str,
) -> Result<PgRow, Response> {
    sqlx::query(
        r#"
INSERT INTO aegaeon.clients (
  environment_id,
  configuration_version_id,
  oauth_profile_id,
  client_identifier,
  name,
  client_type,
  redirect_uris,
  allowed_grant_types,
  allowed_scopes,
  token_endpoint_authentication_method
)
VALUES ($1, $2, $3, $4, $5, $6::aegaeon.client_type, $7, $8, $9, $10)
RETURNING
  id,
  environment_id,
  oauth_profile_id,
  client_identifier,
  name,
  client_type::text AS client_type,
  redirect_uris,
  allowed_grant_types,
  allowed_scopes,
  token_endpoint_authentication_method,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(input.oauth_profile_id)
    .bind(&input.client_identifier)
    .bind(&input.name)
    .bind(&input.client_type)
    .bind(&input.redirect_uris)
    .bind(&input.allowed_grant_types)
    .bind(&input.allowed_scopes)
    .bind(&input.token_endpoint_authentication_method)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to create client",
            None,
            Some(request_id),
        )
    })
}
