use super::super::super::configuration_documents::{
    build_policy_patch_configuration, ConfigurationVersionAuditContext,
    ConfigurationVersionTransition,
};
use super::super::super::{
    begin_management_transaction, commit_management_transaction, environment_from_locked_context,
    parse_uuid_param, require_environment_lifecycle_scope,
    require_team_lifecycle_role_in_transaction,
    runtime_activation_status_for_management_database_write,
};
use super::super::audit::write_policy_patch_audit;
use super::super::policy_patch::{
    create_policy_patch_configuration_version, load_policy_patch_base_context,
};
use crate::management::types::{PolicyPatchRequest, PolicyPatchResponse};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn patch_policies_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    session: &ManagementSession,
    req: &PolicyPatchRequest,
    request_id: &str,
) -> Result<PolicyPatchResponse, Response> {
    let scope = require_environment_lifecycle_scope(
        pool,
        params,
        session,
        request_id,
        "Insufficient permissions for policy operations",
    )
    .await?;
    let base_configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for policy operations",
    )
    .await?;
    let (environment, current_document) =
        load_policy_patch_base_context(&mut tx, scope, base_configuration_version_id, request_id)
            .await?;
    let draft = build_policy_patch_configuration(current_document, &environment, req, request_id)?;
    let (configuration_version_id, updated_at) = create_policy_patch_configuration_version(
        &mut tx,
        &environment,
        session.administrator_id,
        req,
        &draft,
        request_id,
    )
    .await?;

    let audit_context = ConfigurationVersionAuditContext {
        scope: environment.scope,
        administrator_id: session.administrator_id,
        request_id,
        transition: ConfigurationVersionTransition {
            from_configuration_version_id: environment.active_configuration_version_id,
            to_configuration_version_id: configuration_version_id,
        },
    };
    write_policy_patch_audit(&mut tx, &audit_context, req, &draft.downgraded_fields).await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(PolicyPatchResponse {
        policy: draft.configuration.state.policy.clone(),
        environment: environment_from_locked_context(
            &environment,
            configuration_version_id,
            updated_at,
        ),
        runtime_activation: runtime_activation_status_for_management_database_write(),
    })
}
