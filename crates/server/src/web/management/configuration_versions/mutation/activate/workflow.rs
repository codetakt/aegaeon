mod loading;
mod persist;

use super::super::super::super::configuration_documents::{
    ConfigurationVersionAuditContext, ConfigurationVersionTransition,
};
use super::super::super::super::policy_patch::{
    require_security_downgrade_authorization, SecurityDowngradeAuthorization,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, environment_from_locked_context,
    require_environment_lifecycle_scope, require_team_lifecycle_role_in_transaction,
};
use super::super::super::audit::write_configuration_activation_audits;
use crate::management::types::{ActivateConfigurationVersionRequest, EnvironmentMutationResponse};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn activate_configuration_version_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentConfigurationVersionPath,
    request: &ActivateConfigurationVersionRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<EnvironmentMutationResponse, Response> {
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
    let loading::ActivationLoadedContext {
        environment,
        previous_policy,
        previous_audit_snapshot,
        activated_configuration,
    } = loading::load_activation_context(
        &mut tx,
        scope.team,
        scope.environment,
        configuration_version_id,
        request_id,
    )
    .await?;
    let downgraded_fields = require_security_downgrade_authorization(
        &previous_policy,
        &activated_configuration.state.policy,
        SecurityDowngradeAuthorization {
            allowed: request.allow_security_downgrade == Some(true),
            reason: request.reason.as_deref(),
        },
        request_id,
    )?;
    let updated_at = persist::persist_activation_state(
        &mut tx,
        &environment,
        configuration_version_id,
        &activated_configuration,
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
    write_configuration_activation_audits(
        &mut tx,
        &audit_context,
        request,
        &downgraded_fields,
        &previous_audit_snapshot,
        &activated_configuration.audit_snapshot,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(EnvironmentMutationResponse {
        environment: environment_from_locked_context(
            &environment,
            configuration_version_id,
            updated_at,
        ),
    })
}
