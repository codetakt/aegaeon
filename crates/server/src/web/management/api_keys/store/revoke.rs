use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::web::management::management_internal_error;

pub(in crate::web::management::api_keys) async fn revoke_api_key_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    api_key_id: Uuid,
    administrator_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    let row = sqlx::query(
        r"
UPDATE aegaeon.api_keys
SET status = 'REVOKED', revoked_at = now(), revoked_by_administrator_id = $3
WHERE id = $1 AND team_id = $2 AND status = 'ACTIVE'
RETURNING service_administrator_id
        ",
    )
    .bind(api_key_id)
    .bind(team_id)
    .bind(administrator_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to revoke API key"))?;

    let Some(row) = row else {
        return Ok(false);
    };
    let service_administrator_id: Uuid = row
        .try_get("service_administrator_id")
        .map_err(|_| management_internal_error(request_id, "Invalid API key row"))?;

    disable_service_administrator(tx, service_administrator_id, request_id).await?;
    remove_service_team_membership(tx, team_id, service_administrator_id, request_id).await?;

    Ok(true)
}

async fn disable_service_administrator(
    tx: &mut Transaction<'_, Postgres>,
    service_administrator_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
UPDATE aegaeon.administrators
SET status = 'DISABLED', updated_at = now()
WHERE id = $1 AND kind = 'SERVICE'
        ",
    )
    .bind(service_administrator_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| management_internal_error(request_id, "Failed to disable API key principal"))
}

async fn remove_service_team_membership(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    service_administrator_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
DELETE FROM aegaeon.team_memberships
WHERE team_id = $1 AND administrator_id = $2
        ",
    )
    .bind(team_id)
    .bind(service_administrator_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| management_internal_error(request_id, "Failed to remove API key membership"))
}
