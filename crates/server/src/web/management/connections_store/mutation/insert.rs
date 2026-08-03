use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::connections_support::ConnectionInput;
use super::super::super::management_internal_error;

pub(in crate::web::management) async fn insert_connection_row(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    oauth_profile_id: Option<Uuid>,
    input: &ConnectionInput,
    request_id: &str,
) -> Result<PgRow, Response> {
    sqlx::query(
        r#"
INSERT INTO aegaeon.connections (
  environment_id,
  configuration_version_id,
  oauth_profile_id,
  connection_identifier,
  name,
  connection_type,
  issuer_url,
  client_id,
  client_auth_method,
  status
)
VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6::aegaeon.connection_type,
  $7,
  $8,
  $9,
  $10::aegaeon.connection_status
)
RETURNING
  id,
  environment_id,
  configuration_version_id,
  oauth_profile_id,
  connection_identifier,
  name,
  connection_type::text AS connection_type,
  issuer_url,
  client_id,
  client_auth_method,
  status::text AS status,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(oauth_profile_id)
    .bind(&input.connection_identifier)
    .bind(&input.name)
    .bind(&input.connection_type)
    .bind(&input.issuer_url)
    .bind(&input.client_id)
    .bind(&input.client_auth_method)
    .bind(&input.status)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to create connection"))
}
