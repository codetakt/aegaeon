use super::{error_response, normalize_lower_list};
use crate::policy::validate_supported_grant_types;
use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(super) struct ClientInput {
    pub(super) client_identifier: String,
    pub(super) name: String,
    pub(super) client_type: String,
    pub(super) redirect_uris: Vec<String>,
    pub(super) allowed_grant_types: Vec<String>,
    pub(super) allowed_scopes: Vec<String>,
    pub(super) token_endpoint_authentication_method: String,
    pub(super) oauth_profile_id: Option<Uuid>,
}

fn client_input_allows_redirect_flow(input: &ClientInput) -> bool {
    input
        .allowed_grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
}

pub(super) fn validate_management_client_input(
    input: &mut ClientInput,
    request_id: &str,
) -> Result<(), Response> {
    input.client_identifier = input.client_identifier.trim().to_string();
    input.name = input.name.trim().to_string();
    input.client_type = input.client_type.trim().to_string();
    input.allowed_grant_types = normalize_lower_list(&input.allowed_grant_types);
    input.allowed_scopes = normalize_scope_token_list(&input.allowed_scopes, request_id)?;
    input.token_endpoint_authentication_method = input
        .token_endpoint_authentication_method
        .trim()
        .to_ascii_lowercase();

    if input.client_identifier.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "clientIdentifier must not be empty",
            None,
            Some(request_id),
        ));
    }
    if input.name.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "name must not be empty",
            None,
            Some(request_id),
        ));
    }
    if !matches!(input.client_type.as_str(), "PUBLIC" | "CONFIDENTIAL") {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "clientType must be PUBLIC or CONFIDENTIAL",
            None,
            Some(request_id),
        ));
    }
    if input.allowed_grant_types.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "allowedGrantTypes must not be empty",
            None,
            Some(request_id),
        ));
    }
    if input
        .allowed_grant_types
        .iter()
        .any(|grant| grant == "password")
    {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "allowedGrantTypes cannot include password",
            None,
            Some(request_id),
        ));
    }
    validate_supported_grant_types(&input.allowed_grant_types).map_err(|error| {
        let message = error.to_string();
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &message,
            None,
            Some(request_id),
        )
    })?;
    if !matches!(
        input.token_endpoint_authentication_method.as_str(),
        "client_secret_basic" | "client_secret_post" | "private_key_jwt" | "none"
    ) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "tokenEndpointAuthenticationMethod must be client_secret_basic, client_secret_post, private_key_jwt, or none",
            None,
            Some(request_id),
        ));
    }
    if input.token_endpoint_authentication_method == "private_key_jwt" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "private_key_jwt for management-plane clients requires JWKS/JWKS URI support; use DCR or configure a client secret method",
            None,
            Some(request_id),
        ));
    }
    if input.client_type == "PUBLIC" && input.token_endpoint_authentication_method != "none" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PUBLIC clients must use tokenEndpointAuthenticationMethod=none",
            None,
            Some(request_id),
        ));
    }
    if input.client_type == "CONFIDENTIAL" && input.token_endpoint_authentication_method == "none" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CONFIDENTIAL clients must use a client authentication method",
            None,
            Some(request_id),
        ));
    }
    if input.redirect_uris.is_empty() && client_input_allows_redirect_flow(input) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirectUris must not be empty for redirect-based flows",
            None,
            Some(request_id),
        ));
    }

    Ok(())
}

fn normalize_scope_token_list(
    values: &[String],
    request_id: &str,
) -> Result<Vec<String>, Response> {
    let mut normalized = std::collections::BTreeSet::new();
    for value in values {
        let scope = value.trim();
        if scope.is_empty() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "allowedScopes entries must not be blank",
                None,
                Some(request_id),
            ));
        }
        if !crate::oauth_scope::is_scope_token(scope) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "allowedScopes entries must be RFC 6749 scope-token values",
                None,
                Some(request_id),
            ));
        }
        normalized.insert(scope.to_string());
    }
    Ok(normalized.into_iter().collect())
}
