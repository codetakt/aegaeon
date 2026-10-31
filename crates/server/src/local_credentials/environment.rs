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

    let mut connection =
        crate::dcr_persistence::admitted_connection::AdmittedConnection::acquire(pool).await?;
    let result = async {
        let row = sqlx::query(
            r"
SELECT rt.team_id, rt.tenant_id, rt.environment_id
FROM aegaeon.active_runtime_environments rt
WHERE rt.issuer_host = $1
LIMIT 1
        ",
        )
        .bind(issuer_host)
        .fetch_optional(connection.as_mut()?)
        .await?;

        let context = row
            .as_ref()
            .map(runtime_environment_context_from_row)
            .transpose()?;
        if let Some(context) = &context {
            crate::organizations::request_work::async_store::ensure_environment_if_scoped(
                context.environment_id,
            )?;
        }
        Ok(context)
    }
    .await;
    connection.release().await;
    crate::organizations::request_work::async_store::task_owner()?;
    result
}

/// User UUIDs retain permanent Environment ownership; a supplied ID cannot select
/// another Environment inside an entered task. Ordinary management is unchanged.
pub(super) async fn ensure_user_if_scoped(
    connection: &mut sqlx::PgConnection,
    user: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    if crate::organizations::request_work::async_store::task_owner()?.is_none() {
        return Ok(());
    }
    let environment: uuid::Uuid =
        sqlx::query_scalar("SELECT environment_id FROM aegaeon.end_users WHERE id=$1")
            .bind(user)
            .fetch_optional(connection)
            .await?
            .ok_or_else(|| sqlx::Error::Protocol("Organizations credential user missing".into()))?;
    crate::organizations::request_work::async_store::ensure_environment_if_scoped(environment)
}

#[cfg(test)]
mod epoch_tests;
