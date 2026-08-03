use super::super::super::connections_store::{
    ensure_connection_identifier_available, validate_connection_oauth_profile_reference,
};
use super::super::super::connections_support::{
    connection_client_secret_action_from_create, connection_input_from_create,
    resolve_connection_client_secret_action, validate_connection_input,
};
use super::super::super::{
    ensure_base_configuration_matches, load_management_configuration_policy,
    parse_optional_uuid_param, parse_uuid_param, ManagementEnvironmentRecord,
};
use super::PreparedConnectionCreate;
use crate::management::types::CreateConnectionRequest;
use axum::response::Response;
use sqlx::PgPool;

pub(in crate::web::management::connections) async fn prepare_connection_create(
    pool: &PgPool,
    environment: &ManagementEnvironmentRecord,
    req: &CreateConnectionRequest,
    request_id: &str,
) -> Result<PreparedConnectionCreate, Response> {
    let base_configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;
    ensure_base_configuration_matches(base_configuration_version_id, environment, request_id)?;
    load_management_configuration_policy(
        pool,
        environment,
        base_configuration_version_id,
        request_id,
    )
    .await?;

    let mut input = connection_input_from_create(req);
    validate_connection_input(&mut input, request_id)?;
    let client_secret_action = resolve_connection_client_secret_action(
        &input,
        connection_client_secret_action_from_create(req),
        false,
        request_id,
    )?;
    let oauth_profile_id = parse_optional_uuid_param(
        input.oauth_profile_id.as_deref(),
        "oauthProfileId",
        request_id,
    )?;
    validate_connection_oauth_profile_reference(
        pool,
        environment.scope.environment,
        base_configuration_version_id,
        oauth_profile_id,
        request_id,
    )
    .await?;
    ensure_connection_identifier_available(
        pool,
        environment.scope.environment,
        &input.connection_identifier,
        None,
        request_id,
    )
    .await?;

    Ok(PreparedConnectionCreate {
        input,
        configuration_version_id: base_configuration_version_id,
        oauth_profile_id,
        client_secret_action,
    })
}
