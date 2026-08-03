use axum::{
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use std::net::SocketAddr;

use super::super::super::oauth_errors::{
    no_cache_json_error_with_iss, registry_state_error_response,
};
use super::super::super::request_admission::{enforce_content_type, enforce_no_credentials_in_uri};
use super::super::super::{
    downstream_profile_violation_response, resolve_downstream_profile_for_endpoint,
    transport_rejection, validate_downstream_device_profile_policy, AppState,
    DEVICE_CODE_GRANT_TYPE,
};
use super::client_auth::DeviceAuthorizationClientContext;

pub(super) fn enforce_device_authorization_admission(
    state: &AppState,
    remote: SocketAddr,
    uri: &Uri,
    headers: &HeaderMap,
    issuer_base: &str,
) -> Result<(), Response> {
    if !state.cfg.grant_runtime().device_authorization_enabled() {
        return Err(no_cache_json_error_with_iss(
            StatusCode::NOT_FOUND,
            "not_found",
            None,
            issuer_base,
        ));
    }
    if let Err(kind) = state.transport.enforce(Some(remote), headers) {
        return Err(transport_rejection(state, kind));
    }
    enforce_no_credentials_in_uri(uri, issuer_base)?;
    enforce_content_type(headers, "application/x-www-form-urlencoded", issuer_base)
}

pub(super) async fn enforce_device_authorization_policy(
    state: &AppState,
    issuer_base: &str,
    client_context: &DeviceAuthorizationClientContext,
    requested_scopes: &[String],
) -> Result<(), Response> {
    let profile = resolve_downstream_profile_for_endpoint(
        state,
        issuer_base,
        &client_context.client_id,
        "device_authorization",
    )
    .await?;
    if let Err(violation) =
        validate_downstream_device_profile_policy(&profile, client_context.client_auth_method)
    {
        return Err(downstream_profile_violation_response(
            violation,
            "device_authorization",
            "device_authorization",
            issuer_base,
        ));
    }
    let grant_allowed = state
        .clients
        .try_allows_grant(&client_context.client_id, DEVICE_CODE_GRANT_TYPE)
        .map_err(|error| {
            registry_state_error_response(issuer_base, "device_authorization_allows_grant", error)
        })?;
    if !grant_allowed {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            Some("client is not authorized for the device_code grant type"),
            issuer_base,
        ));
    }
    let scope_allowed = if requested_scopes.is_empty() {
        true
    } else {
        state
            .clients
            .try_validate_scope_subset(&client_context.client_id, requested_scopes)
            .map_err(|error| {
                registry_state_error_response(
                    issuer_base,
                    "device_authorization_validate_scope_subset",
                    error,
                )
            })?
    };
    if !scope_allowed {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some("requested scope is not allowed for this client"),
            issuer_base,
        ));
    }
    Ok(())
}
