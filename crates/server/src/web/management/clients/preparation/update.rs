use super::super::super::{
    ensure_base_configuration_matches, error_response, parse_uuid_param, validate_redirect_uris,
    ManagementEnvironmentRecord,
};
use super::oauth_profile::validate_client_oauth_profile_change;
use super::{ClientOAuthProfileChange, ClientUpdateInput, PreparedClientUpdate};
use crate::management::types::UpdateClientRequest;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(in crate::web::management::clients) async fn prepare_client_update(
    pool: &PgPool,
    environment: &ManagementEnvironmentRecord,
    req: &UpdateClientRequest,
    request_id: &str,
) -> Result<PreparedClientUpdate, Response> {
    if !client_update_requested(req) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "No updatable fields provided",
            None,
            Some(request_id),
        ));
    }

    if let Some(name) = req.name.as_deref() {
        if name.trim().is_empty() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Client name must not be empty",
                None,
                Some(request_id),
            ));
        }
    }

    let configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;
    ensure_base_configuration_matches(configuration_version_id, environment, request_id)?;

    let redirect_uris = req
        .redirect_uris
        .as_ref()
        .map(|uris| validate_redirect_uris(uris, request_id))
        .transpose()?;
    let oauth_profile_change = match &req.oauth_profile_id {
        Some(Some(profile_id)) => Some(ClientOAuthProfileChange::Assign(parse_uuid_param(
            profile_id,
            "oauthProfileId",
            request_id,
        )?)),
        Some(None) => Some(ClientOAuthProfileChange::Clear),
        None => None,
    };
    validate_client_oauth_profile_change(
        pool,
        environment.scope.environment,
        configuration_version_id,
        oauth_profile_change,
        request_id,
    )
    .await?;

    Ok(PreparedClientUpdate {
        input: ClientUpdateInput {
            name: req.name.clone(),
            redirect_uris,
            allowed_grant_types: req.allowed_grant_types.clone(),
            allowed_scopes: req.allowed_scopes.clone(),
            token_endpoint_authentication_method: req.token_endpoint_authentication_method.clone(),
            oauth_profile_change,
        },
        configuration_version_id,
    })
}

fn client_update_requested(req: &UpdateClientRequest) -> bool {
    req.name.is_some()
        || req.redirect_uris.is_some()
        || req.allowed_grant_types.is_some()
        || req.allowed_scopes.is_some()
        || req.token_endpoint_authentication_method.is_some()
        || req.oauth_profile_id.is_some()
        || req.comment.is_some()
}
