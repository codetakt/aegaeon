use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::Client;

use super::super::super::super::client_input::ClientInput;
use super::super::super::super::management_internal_error;
use super::super::super::mapper::client_from_row_result;

pub(in crate::web::management) const UPDATE_CLIENT_ROW_SQL: &str = r#"
UPDATE aegaeon.clients c
SET
  name = $1,
  redirect_uris = $2,
  allowed_grant_types = $3,
  allowed_scopes = $4,
  token_endpoint_authentication_method = $5,
  oauth_profile_id = $6,
  updated_at = now()
FROM aegaeon.environments e
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE c.id = $7
  AND c.environment_id = $8
  AND c.configuration_version_id = $9
  AND c.status <> 'DELETED'
  AND e.id = c.environment_id
  AND e.status <> 'DELETED'
  AND e.active_configuration_version_id = $9
  AND t.status <> 'DELETED'
  AND t.team_id = $10
RETURNING
  c.id,
  c.environment_id,
  c.oauth_profile_id,
  c.client_identifier,
  c.name,
  c.client_type::text AS client_type,
  c.redirect_uris,
  c.allowed_grant_types,
  c.allowed_scopes,
  c.token_endpoint_authentication_method,
  to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(c.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#;

pub(in crate::web::management) async fn update_client_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    configuration_version_id: Uuid,
    input: &ClientInput,
    request_id: &str,
) -> Result<Option<Client>, Response> {
    let row = sqlx::query(UPDATE_CLIENT_ROW_SQL)
        .bind(&input.name)
        .bind(&input.redirect_uris)
        .bind(&input.allowed_grant_types)
        .bind(&input.allowed_scopes)
        .bind(&input.token_endpoint_authentication_method)
        .bind(input.oauth_profile_id)
        .bind(client_id)
        .bind(environment_id)
        .bind(configuration_version_id)
        .bind(team_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to update client"))?;

    row.map(|row| client_from_row_result(&row, request_id))
        .transpose()
}
