use super::super::super::super::configuration_documents::{
    prepare_configuration_document, validate_configuration_version_document,
};
use super::super::super::super::configuration_version_store::{
    configuration_version_from_row_result, insert_configuration_version_row,
    load_next_configuration_version_number,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    load_locked_environment_mutation_context, management_internal_error, parse_uuid_param,
    require_environment_lifecycle_scope, require_team_lifecycle_role_in_transaction,
};
use crate::management::types::{ConfigurationVersion, CreateConfigurationVersionRequest};
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn create_configuration_version_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    session: &ManagementSession,
    req: &CreateConfigurationVersionRequest,
    request_id: &str,
) -> Result<ConfigurationVersion, Response> {
    let base_configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;
    let scope = require_environment_lifecycle_scope(
        pool,
        params,
        session,
        request_id,
        "Insufficient permissions for configuration version operations",
    )
    .await?;
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

    if environment_context.active_configuration_version_id != base_configuration_version_id {
        return Err(error_response(
            StatusCode::CONFLICT,
            "base_version_mismatch",
            "baseConfigurationVersionId did not match the active configuration version",
            None,
            Some(request_id),
        ));
    }
    validate_configuration_version_document(
        &req.configuration_document,
        &environment_context.issuer_host,
        &environment_context.issuer_url,
        request_id,
    )?;
    let prepared_document =
        prepare_configuration_document(&req.configuration_document, request_id)?;

    let next_version_number = load_next_configuration_version_number(
        &mut tx,
        environment_context.scope.environment,
        request_id,
    )
    .await?;
    let row = insert_configuration_version_row(
        &mut tx,
        environment_context.scope.environment,
        next_version_number,
        base_configuration_version_id,
        session.administrator_id,
        req.comment.as_deref(),
        &prepared_document,
    )
    .await
    .map_err(|_| {
        error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Failed to create configuration version",
            None,
            Some(request_id),
        )
    })?;
    commit_management_transaction(tx, request_id).await?;

    configuration_version_from_row_result(&row, request_id).map_err(|_| {
        management_internal_error(request_id, "Failed to read created configuration version")
    })
}
