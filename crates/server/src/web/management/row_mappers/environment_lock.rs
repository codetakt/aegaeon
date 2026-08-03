use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::configuration_documents::LockedEnvironmentMutationContext;
use super::super::{
    management_environment_not_found, management_internal_error, required_row_value,
    ManagementEnvironmentScope,
};

pub(in crate::web::management) async fn load_locked_environment_mutation_context(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<LockedEnvironmentMutationContext, Response> {
    let row = sqlx::query(
        r#"
SELECT
  e.tenant_id,
  e.name,
  e.slug,
  e.issuer_host,
  e.issuer_url,
  e.active_configuration_version_id,
  to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
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
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let Some(row) = row else {
        return Err(management_environment_not_found(request_id));
    };

    let tenant_id: Uuid = row
        .try_get("tenant_id")
        .map_err(|_| management_internal_error(request_id, "Failed to read environment row"))?;
    let active_configuration_version_id: Option<Uuid> = row
        .try_get("active_configuration_version_id")
        .map_err(|_| management_internal_error(request_id, "Failed to read environment row"))?;
    let active_configuration_version_id = active_configuration_version_id.ok_or_else(|| {
        management_internal_error(
            request_id,
            "Environment is missing an active configuration version",
        )
    })?;
    let name = required_row_value(&row, "name", request_id, "Failed to read environment row")?;
    let slug = required_row_value(&row, "slug", request_id, "Failed to read environment row")?;
    let issuer_host: String = required_row_value(
        &row,
        "issuer_host",
        request_id,
        "Failed to read environment row",
    )?;
    let issuer_url = required_row_value(
        &row,
        "issuer_url",
        request_id,
        "Failed to read environment row",
    )?;
    let created_at = required_row_value(
        &row,
        "created_at",
        request_id,
        "Failed to read environment row",
    )?;

    Ok(LockedEnvironmentMutationContext {
        scope: ManagementEnvironmentScope {
            team: team_id,
            tenant: tenant_id,
            environment: environment_id,
        },
        name,
        slug,
        issuer_host,
        issuer_url,
        created_at,
        active_configuration_version_id,
    })
}
