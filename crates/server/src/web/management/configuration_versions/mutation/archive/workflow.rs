use super::super::super::super::configuration_documents::{
    ConfigurationVersionAuditContext, ConfigurationVersionTransition,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    load_locked_environment_mutation_context, management_internal_error,
    require_environment_lifecycle_scope, require_team_lifecycle_role_in_transaction,
};
use super::super::super::audit::write_configuration_archive_audit;
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) async fn archive_configuration_version_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentConfigurationVersionPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let scope = require_environment_lifecycle_scope(
        pool,
        params,
        session,
        request_id,
        "Insufficient permissions for configuration version operations",
    )
    .await?;
    let configuration_version_id = params.configuration_version_id(request_id)?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for configuration version operations",
    )
    .await?;
    let environment_context = load_locked_environment_mutation_context(
        &mut tx,
        scope.team,
        scope.environment,
        request_id,
    )
    .await?;
    let target_status = load_configuration_version_status_for_update(
        &mut tx,
        environment_context.scope.environment,
        configuration_version_id,
        request_id,
    )
    .await?;

    if environment_context.active_configuration_version_id == configuration_version_id
        || target_status == ConfigurationVersionStatus::Active
    {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Cannot archive the active configuration version",
            None,
            Some(request_id),
        ));
    }

    if target_status == ConfigurationVersionStatus::Archived {
        commit_management_transaction(tx, request_id).await?;
        return Ok(());
    }

    sqlx::query(
        r"
UPDATE aegaeon.configuration_versions
SET status = 'ARCHIVED', archived_at = now()
WHERE id = $1
  AND environment_id = $2
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_context.scope.environment)
    .execute(&mut *tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let audit_context = ConfigurationVersionAuditContext {
        scope: environment_context.scope,
        administrator_id: session.administrator_id,
        request_id,
        transition: ConfigurationVersionTransition {
            from_configuration_version_id: environment_context.active_configuration_version_id,
            to_configuration_version_id: configuration_version_id,
        },
    };
    write_configuration_archive_audit(&mut tx, &audit_context, configuration_version_id).await?;
    commit_management_transaction(tx, request_id).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigurationVersionStatus {
    Active,
    Archived,
    Other,
}

impl ConfigurationVersionStatus {
    fn from_database_value(status: &str) -> Self {
        match status {
            "ACTIVE" => Self::Active,
            "ARCHIVED" => Self::Archived,
            _ => Self::Other,
        }
    }
}

async fn load_configuration_version_status_for_update(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<ConfigurationVersionStatus, Response> {
    let exists = sqlx::query(
        r"
SELECT cv.status::text AS status
FROM aegaeon.configuration_versions cv
WHERE cv.id = $1
  AND cv.environment_id = $2
FOR UPDATE OF cv
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let Some(row) = exists else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Configuration version not found",
            None,
            Some(request_id),
        ));
    };

    let status: String = row.try_get("status").map_err(|_| {
        management_internal_error(request_id, "Failed to read configuration status")
    })?;
    Ok(ConfigurationVersionStatus::from_database_value(&status))
}
