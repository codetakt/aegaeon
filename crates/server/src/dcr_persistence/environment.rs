use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use super::DcrDatabaseError;

#[derive(Clone, Copy, Debug)]
pub(super) struct ActiveDcrEnvironment {
    pub(super) team_id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) environment_id: Uuid,
    pub(super) configuration_version_id: Uuid,
}

pub(super) async fn load_active_environment(
    pool: &PgPool,
    issuer_host: &str,
) -> Result<ActiveDcrEnvironment, DcrDatabaseError> {
    let issuer_host = normalize_issuer_host(issuer_host)?;
    let rows = sqlx::query(
        r"
SELECT
  rt.team_id,
  rt.tenant_id,
  rt.environment_id,
  rt.configuration_version_id
FROM aegaeon.active_runtime_environments rt
WHERE rt.issuer_host = $1
        ",
    )
    .bind(issuer_host)
    .fetch_all(pool)
    .await?;

    match rows.as_slice() {
        [] => Err(DcrDatabaseError::EnvironmentNotFound(
            issuer_host.to_string(),
        )),
        [row] => Ok(ActiveDcrEnvironment {
            team_id: row.try_get("team_id")?,
            tenant_id: row.try_get("tenant_id")?,
            environment_id: row.try_get("environment_id")?,
            configuration_version_id: row.try_get("configuration_version_id")?,
        }),
        _ => Err(DcrDatabaseError::MultipleEnvironments(
            issuer_host.to_string(),
        )),
    }
}

pub(super) async fn load_active_environment_for_update(
    tx: &mut Transaction<'_, Postgres>,
    issuer_host: &str,
) -> Result<ActiveDcrEnvironment, DcrDatabaseError> {
    let issuer_host = normalize_issuer_host(issuer_host)?;
    let rows = sqlx::query(
        r"
SELECT
  rt.team_id,
  rt.tenant_id,
  rt.environment_id,
  rt.configuration_version_id
FROM aegaeon.active_runtime_environments rt
JOIN aegaeon.environments e
  ON e.id = rt.environment_id
WHERE rt.issuer_host = $1
FOR UPDATE OF e
        ",
    )
    .bind(issuer_host)
    .fetch_all(&mut **tx)
    .await?;

    match rows.as_slice() {
        [] => Err(DcrDatabaseError::EnvironmentNotFound(
            issuer_host.to_string(),
        )),
        [row] => Ok(ActiveDcrEnvironment {
            team_id: row.try_get("team_id")?,
            tenant_id: row.try_get("tenant_id")?,
            environment_id: row.try_get("environment_id")?,
            configuration_version_id: row.try_get("configuration_version_id")?,
        }),
        _ => Err(DcrDatabaseError::MultipleEnvironments(
            issuer_host.to_string(),
        )),
    }
}

pub(super) fn normalize_issuer_host(issuer_host: &str) -> Result<&str, DcrDatabaseError> {
    let issuer_host = issuer_host.trim();
    if issuer_host.is_empty() {
        Err(DcrDatabaseError::EmptyIssuerHost)
    } else {
        Ok(issuer_host)
    }
}
