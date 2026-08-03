use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::Client;

use super::super::super::super::management_internal_error;
use super::super::super::mapper::client_from_row_result;

pub(in crate::web::management) const LOAD_CLIENT_FOR_UPDATE_SQL: &str = r#"
SELECT
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
FROM aegaeon.clients c
JOIN aegaeon.environments e
  ON e.id = c.environment_id
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE c.id = $1
  AND c.environment_id = $2
  AND c.configuration_version_id = $3
  AND c.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND e.active_configuration_version_id = $3
  AND t.status <> 'DELETED'
  AND t.team_id = $4
FOR UPDATE OF c
        "#;

pub(in crate::web::management) async fn load_client_for_update(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<Option<Client>, Response> {
    let row = sqlx::query(LOAD_CLIENT_FOR_UPDATE_SQL)
        .bind(client_id)
        .bind(environment_id)
        .bind(configuration_version_id)
        .bind(team_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to load client"))?;

    row.map(|row| client_from_row_result(&row, request_id))
        .transpose()
}
