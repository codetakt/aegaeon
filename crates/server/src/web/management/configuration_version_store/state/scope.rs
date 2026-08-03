use super::super::super::management_internal_error;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn replace_environment_scope_allowlist_state(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    scope_allowlist: &[String],
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query("DELETE FROM aegaeon.environment_scope_allowlist WHERE environment_id = $1")
        .bind(environment_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| {
            management_internal_error(request_id, "Failed to update environment scope allowlist")
        })?;

    for scope in scope_allowlist {
        sqlx::query(
            r"
INSERT INTO aegaeon.environment_scope_allowlist (environment_id, configuration_version_id, scope)
VALUES ($1, $2, $3)
ON CONFLICT (environment_id, scope) DO UPDATE
SET configuration_version_id = EXCLUDED.configuration_version_id
            ",
        )
        .bind(environment_id)
        .bind(configuration_version_id)
        .bind(scope)
        .execute(&mut **tx)
        .await
        .map_err(|_| {
            management_internal_error(request_id, "Failed to update environment scope allowlist")
        })?;
    }

    Ok(())
}
