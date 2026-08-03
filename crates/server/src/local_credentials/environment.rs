use sqlx::PgPool;

use super::identity::issuer_host_from_url;
use super::rows::runtime_environment_context_from_row;
use super::types::RuntimeEnvironmentContext;

/// # Errors
///
/// Returns any `SQLx` error produced while resolving the issuer environment.
pub async fn load_runtime_environment_context(
    pool: &PgPool,
    issuer: &str,
) -> Result<Option<RuntimeEnvironmentContext>, sqlx::Error> {
    let Some(issuer_host) = issuer_host_from_url(issuer) else {
        return Ok(None);
    };

    let row = sqlx::query(
        r"
SELECT rt.team_id, rt.tenant_id, rt.environment_id
FROM aegaeon.active_runtime_environments rt
WHERE rt.issuer_host = $1
LIMIT 1
        ",
    )
    .bind(issuer_host)
    .fetch_optional(pool)
    .await?;

    row.as_ref()
        .map(runtime_environment_context_from_row)
        .transpose()
}
