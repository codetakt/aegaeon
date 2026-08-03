use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::management_internal_error;

pub(in crate::web::management) const DELETE_CLIENT_ROW_SQL: &str = r"
UPDATE aegaeon.clients c
SET status = 'DELETED', deleted_at = now(), updated_at = now()
FROM aegaeon.environments e
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE c.id = $1
  AND c.environment_id = $2
  AND c.configuration_version_id = $4
  AND c.status <> 'DELETED'
  AND e.id = c.environment_id
  AND e.status <> 'DELETED'
  AND e.active_configuration_version_id = $4
  AND t.status <> 'DELETED'
  AND t.team_id = $3
RETURNING c.client_identifier
        ";

pub(in crate::web::management) async fn delete_client_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(DELETE_CLIENT_ROW_SQL)
        .bind(client_id)
        .bind(environment_id)
        .bind(team_id)
        .bind(configuration_version_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to delete client"))
}
