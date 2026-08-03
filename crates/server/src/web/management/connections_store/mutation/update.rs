use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::connections_support::ConnectionInput;
use super::super::super::management_internal_error;

pub(in crate::web::management) async fn update_connection_row(
    tx: &mut Transaction<'_, Postgres>,
    connection_id: Uuid,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    oauth_profile_id: Option<Uuid>,
    input: &ConnectionInput,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
UPDATE aegaeon.connections
SET
  oauth_profile_id = $3,
  connection_identifier = $4,
  name = $5,
  connection_type = $6::aegaeon.connection_type,
  client_id = $7,
  client_auth_method = $8,
  status = $9::aegaeon.connection_status,
  updated_at = now()
WHERE id = $1
  AND environment_id = $2
  AND configuration_version_id = $10
  AND status <> 'DELETED'
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
    .bind(connection_id)
    .bind(environment_id)
    .bind(oauth_profile_id)
    .bind(&input.connection_identifier)
    .bind(&input.name)
    .bind(&input.connection_type)
    .bind(&input.client_id)
    .bind(&input.client_auth_method)
    .bind(&input.status)
    .bind(configuration_version_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to update connection"))
}
