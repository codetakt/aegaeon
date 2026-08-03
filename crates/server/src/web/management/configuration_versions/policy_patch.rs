use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::configuration_documents::{
    policy_patch_comment, prepare_configuration_document, LockedEnvironmentMutationContext,
    PolicyPatchDraft,
};
use super::super::configuration_version_store::{
    insert_configuration_version_row, load_configuration_document_for_update,
    load_next_configuration_version_number, persist_environment_configuration_state,
    switch_active_configuration_version,
};
use super::super::{
    ensure_no_revocation_conflicts, error_response, load_locked_environment_mutation_context,
    management_internal_error, ManagementEnvironmentScope,
};
use crate::management::types::PolicyPatchRequest;

pub(super) async fn load_policy_patch_base_context(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    base_configuration_version_id: Uuid,
    request_id: &str,
) -> Result<(LockedEnvironmentMutationContext, serde_json::Value), Response> {
    let environment =
        load_locked_environment_mutation_context(tx, scope.team, scope.environment, request_id)
            .await?;
    if environment.active_configuration_version_id != base_configuration_version_id {
        return Err(error_response(
            StatusCode::CONFLICT,
            "base_version_mismatch",
            "baseConfigurationVersionId did not match the active configuration version",
            None,
            Some(request_id),
        ));
    }

    let configuration_document = load_configuration_document_for_update(
        tx,
        environment.scope.environment,
        environment.active_configuration_version_id,
        request_id,
    )
    .await?;
    Ok((environment, configuration_document))
}

pub(super) async fn create_policy_patch_configuration_version(
    tx: &mut Transaction<'_, Postgres>,
    environment: &LockedEnvironmentMutationContext,
    administrator_id: Uuid,
    request: &PolicyPatchRequest,
    draft: &PolicyPatchDraft,
    request_id: &str,
) -> Result<(Uuid, String), Response> {
    ensure_no_revocation_conflicts(
        tx,
        environment.scope.environment,
        &draft.configuration.configuration_document,
        request_id,
    )
    .await?;

    let prepared_document =
        prepare_configuration_document(&draft.configuration.configuration_document, request_id)?;
    let next_version_number =
        load_next_configuration_version_number(tx, environment.scope.environment, request_id)
            .await?;
    let row = insert_configuration_version_row(
        tx,
        environment.scope.environment,
        next_version_number,
        environment.active_configuration_version_id,
        administrator_id,
        policy_patch_comment(request),
        &prepared_document,
    )
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to create configuration version"))?;
    let configuration_version_id = row.try_get("id").map_err(|_| {
        management_internal_error(request_id, "Failed to read configuration version")
    })?;

    persist_environment_configuration_state(
        tx,
        environment.scope.environment,
        configuration_version_id,
        &draft.configuration.state,
        request_id,
    )
    .await?;

    let updated_at = switch_active_configuration_version(
        tx,
        environment.scope.environment,
        environment.active_configuration_version_id,
        configuration_version_id,
        request_id,
    )
    .await?;
    Ok((configuration_version_id, updated_at))
}
