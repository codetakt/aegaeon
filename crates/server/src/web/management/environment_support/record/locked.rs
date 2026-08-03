use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::super::super::{management_environment_not_found, management_internal_error};
use super::super::rows::environment_row_from_pg_row;
use super::super::types::ManagementEnvironmentRecord;
use super::mapper::management_environment_record_from_row;

pub(in crate::web::management) async fn load_management_environment_record_for_update(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<ManagementEnvironmentRecord, Response> {
    let row = sqlx::query(
        r#"
SELECT
  e.tenant_id,
  e.name,
  e.slug,
  e.issuer_host,
  e.issuer_url,
  e.active_configuration_version_id,
  to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(e.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.environments e
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE e.id = $1
  AND t.team_id = $2
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
FOR UPDATE OF e
        "#,
    )
    .bind(environment_id)
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?
    .map(|row| environment_row_from_pg_row(&row))
    .transpose()
    .map_err(|_| management_internal_error(request_id, "Failed to read environment"))?;

    let Some(row) = row else {
        return Err(management_environment_not_found(request_id));
    };

    management_environment_record_from_row(team_id, environment_id, row, request_id)
}
