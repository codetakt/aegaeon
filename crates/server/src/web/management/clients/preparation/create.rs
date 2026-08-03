use super::super::super::client_input::{validate_management_client_input, ClientInput};
use super::super::super::{
    ensure_base_configuration_matches, error_response, parse_optional_uuid_param, parse_uuid_param,
    validate_redirect_uris, ManagementEnvironmentRecord,
};
use super::oauth_profile::validate_client_oauth_profile_change;
use super::{ClientOAuthProfileChange, PreparedClientCreate};
use crate::management::types::CreateClientRequest;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(in crate::web::management::clients) async fn prepare_client_create(
    pool: &PgPool,
    environment: &ManagementEnvironmentRecord,
    req: &CreateClientRequest,
    request_id: &str,
) -> Result<PreparedClientCreate, Response> {
    let base_configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;
    ensure_base_configuration_matches(base_configuration_version_id, environment, request_id)?;

    let name = req.name.trim();
    if name.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "name is required",
            None,
            Some(request_id),
        ));
    }

    let client_type = req.client_type.trim();
    if !matches!(client_type, "PUBLIC" | "CONFIDENTIAL") {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "clientType must be PUBLIC or CONFIDENTIAL",
            None,
            Some(request_id),
        ));
    }

    let redirect_uris = validate_redirect_uris(&req.redirect_uris, request_id)?;
    let oauth_profile_id = parse_optional_uuid_param(
        req.oauth_profile_id.as_deref(),
        "oauthProfileId",
        request_id,
    )?;
    validate_client_oauth_profile_change(
        pool,
        environment.scope.environment,
        base_configuration_version_id,
        Some(oauth_profile_id.map_or(
            ClientOAuthProfileChange::Clear,
            ClientOAuthProfileChange::Assign,
        )),
        request_id,
    )
    .await?;

    let mut input = ClientInput {
        client_identifier: aegaeon_crypto::rand::random_base64url(24),
        name: name.to_string(),
        client_type: client_type.to_string(),
        redirect_uris,
        allowed_grant_types: req
            .allowed_grant_types
            .clone()
            .unwrap_or_else(|| vec!["authorization_code".to_string()]),
        allowed_scopes: match &req.allowed_scopes {
            Some(allowed_scopes) => allowed_scopes.clone(),
            None => Vec::new(),
        },
        token_endpoint_authentication_method: req
            .token_endpoint_authentication_method
            .clone()
            .unwrap_or_else(|| {
                if client_type == "PUBLIC" {
                    "none".to_string()
                } else {
                    "client_secret_basic".to_string()
                }
            }),
        oauth_profile_id,
    };
    validate_management_client_input(&mut input, request_id)?;

    Ok(PreparedClientCreate {
        input,
        configuration_version_id: environment.active_configuration_version_id,
    })
}
