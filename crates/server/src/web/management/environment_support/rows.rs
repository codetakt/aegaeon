use sqlx::{postgres::PgRow, PgPool, Row};
use uuid::Uuid;

use super::types::EnvironmentRow;

pub(in crate::web::management) async fn load_tenant_slug_and_region(
    pool: &PgPool,
    team_id: Uuid,
    tenant_id: Uuid,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query(
        r"
SELECT slug, region
FROM aegaeon.tenants
WHERE id = $1
  AND team_id = $2
  AND status <> 'DELETED'
        ",
    )
    .bind(tenant_id)
    .bind(team_id)
    .fetch_optional(pool)
    .await?;

    row.map(|row| {
        let slug: String = row.try_get("slug")?;
        let region: String = row.try_get("region")?;
        Ok((slug, region))
    })
    .transpose()
}

pub(in crate::web::management) const LOAD_ENVIRONMENT_ROW_SQL: &str = r#"
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
        "#;

pub(in crate::web::management) fn environment_row_from_pg_row(
    row: &PgRow,
) -> Result<EnvironmentRow, sqlx::Error> {
    let tenant_id: Uuid = row.try_get("tenant_id")?;
    let name: String = row.try_get("name")?;
    let slug: String = row.try_get("slug")?;
    let issuer_host: String = row.try_get("issuer_host")?;
    let issuer_url: String = row.try_get("issuer_url")?;
    let active_configuration_version_id: Option<Uuid> =
        row.try_get("active_configuration_version_id")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;

    Ok((
        tenant_id,
        name,
        slug,
        issuer_host,
        issuer_url,
        active_configuration_version_id,
        created_at,
        updated_at,
    ))
}

pub(in crate::web::management) async fn load_environment_row(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
) -> Result<Option<EnvironmentRow>, sqlx::Error> {
    let row = sqlx::query(LOAD_ENVIRONMENT_ROW_SQL)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(pool)
        .await?;

    row.map(|row| environment_row_from_pg_row(&row)).transpose()
}
