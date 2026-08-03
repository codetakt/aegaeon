use super::super::super::super::{error_response, management_internal_error, required_row_value};
use super::super::super::CreateEnvironmentInput;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(in crate::web::management::topology_support::environment_creation) async fn lock_active_tenant_for_environment_creation(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    tenant_id: Uuid,
    request_id: &str,
) -> Result<Option<(String, String)>, Response> {
    let row = sqlx::query(
        r"
SELECT t.slug, t.region
FROM aegaeon.tenants t
JOIN aegaeon.teams team
  ON team.id = t.team_id
WHERE t.id = $1
  AND t.team_id = $2
  AND t.status = 'ACTIVE'
  AND team.status = 'ACTIVE'
FOR UPDATE OF team, t
        ",
    )
    .bind(tenant_id)
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    row.map(|row| {
        let slug: String = row
            .try_get("slug")
            .map_err(|_| management_internal_error(request_id, "Failed to read tenant row"))?;
        let region: String = row
            .try_get("region")
            .map_err(|_| management_internal_error(request_id, "Failed to read tenant row"))?;
        Ok((slug, region))
    })
    .transpose()
}

pub(in crate::web::management::topology_support::environment_creation) async fn insert_environment_record(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    input: &CreateEnvironmentInput,
    issuer_host: &str,
    request_id: &str,
) -> Result<(Uuid, String), Response> {
    let row = sqlx::query(
        r#"
INSERT INTO aegaeon.environments (tenant_id, name, slug, issuer_host)
VALUES ($1, $2, $3, $4)
RETURNING
  id,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
        "#,
    )
    .bind(tenant_id)
    .bind(&input.name)
    .bind(&input.slug)
    .bind(issuer_host)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to create environment",
            None,
            Some(request_id),
        )
    })?;

    let environment_id = row
        .try_get("id")
        .map_err(|_| management_internal_error(request_id, "Failed to read created environment"))?;
    let created_at = required_row_value(
        &row,
        "created_at",
        request_id,
        "Failed to read created environment",
    )?;
    Ok((environment_id, created_at))
}
