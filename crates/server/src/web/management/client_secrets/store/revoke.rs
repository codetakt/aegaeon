use super::super::super::{client_secret_from_row_result, management_internal_error};
use crate::management::types::ClientSecret;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) const REVOKE_CLIENT_SECRET_ROW_SQL: &str = r#"
UPDATE aegaeon.client_secrets cs
SET status = 'REVOKED', revoked_at = now()
FROM aegaeon.clients c
JOIN aegaeon.environments e ON e.id = c.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE cs.id = $1
  AND cs.client_id = $2
  AND cs.client_id = c.id
  AND c.environment_id = $3
  AND cs.status <> 'REVOKED'
  AND t.team_id = $4
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
RETURNING
  cs.id,
  cs.client_id,
  cs.status::text AS status,
  cs.active_slot,
  to_char(cs.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at,
  to_char(cs.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS expires_at
        "#;

pub(in crate::web::management) const REVOKE_ALL_CLIENT_SECRETS_ROWS_SQL: &str = r"
UPDATE aegaeon.client_secrets cs
SET status = 'REVOKED', revoked_at = now()
FROM aegaeon.clients c
JOIN aegaeon.environments e ON e.id = c.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE cs.client_id = $1
  AND cs.client_id = c.id
  AND c.environment_id = $2
  AND cs.status <> 'REVOKED'
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
RETURNING 1
        ";

pub(in crate::web::management::client_secrets) async fn revoke_client_secret_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    client_secret_id: Uuid,
    request_id: &str,
) -> Result<Option<ClientSecret>, Response> {
    let row = sqlx::query(REVOKE_CLIENT_SECRET_ROW_SQL)
        .bind(client_secret_id)
        .bind(client_id)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to revoke client secret"))?;

    row.map(|row| client_secret_from_row_result(&row, request_id))
        .transpose()
}

pub(in crate::web::management::client_secrets) async fn revoke_all_client_secrets_rows(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    let result = sqlx::query(REVOKE_ALL_CLIENT_SECRETS_ROWS_SQL)
        .bind(client_id)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to revoke client secrets"))?;

    Ok(result.is_some())
}
