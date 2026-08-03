use super::super::super::super::key_stores::normalize_key_store_audit_note;
use super::super::super::super::runtime_key_store::{revoke_runtime_key_row, runtime_key_from_row};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record_for_update,
    parse_uuid_param, require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
    TeamEnvironmentRuntimeKeyPath,
};
use super::super::super::audit::{write_runtime_key_lifecycle_audit, RuntimeKeyLifecycleAudit};
use super::scope::runtime_key_not_found;
use crate::management::types::{ConfigurationTransactionRequest, RuntimeKeyMutationResponse};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(in crate::web::management) async fn revoke_runtime_key_inner(
    pool: &PgPool,
    path: &TeamEnvironmentRuntimeKeyPath,
    req: &ConfigurationTransactionRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<RuntimeKeyMutationResponse, Response> {
    let (team_id, environment_id, runtime_key_id) = path.ids(request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for runtime key operations",
    )
    .await?;
    let base_configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;
    let comment = normalize_key_store_audit_note(req.comment.as_deref(), "comment", request_id)?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for runtime key operations",
    )
    .await?;
    let environment =
        load_management_environment_record_for_update(&mut tx, team_id, environment_id, request_id)
            .await?;
    ensure_base_configuration_matches(base_configuration_version_id, &environment, request_id)?;
    let Some(row) = revoke_runtime_key_row(
        &mut tx,
        team_id,
        environment.scope.environment,
        runtime_key_id,
        request_id,
    )
    .await?
    else {
        return Err(runtime_key_not_found(
            request_id,
            "Runtime key not found or already revoked",
        ));
    };
    let runtime_key = runtime_key_from_row(&row, request_id)?;
    write_runtime_key_lifecycle_audit(
        &mut tx,
        &environment,
        session.administrator_id,
        request_id,
        RuntimeKeyLifecycleAudit {
            runtime_key: &runtime_key,
            event_type: "management.runtimeKey.revoked.v1",
            operation: "REVOKE",
            comment,
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(RuntimeKeyMutationResponse {
        runtime_key,
        environment: environment_from_management_record(&environment),
    })
}
