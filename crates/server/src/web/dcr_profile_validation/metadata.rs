use super::super::dcr_response::invalid_client_metadata_response;
use super::super::AppState;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::dcr::{
    everparse_self_check_registration_with_runtime, validate_registration_with_config,
    ClientRegistration,
};
use crate::util;

pub(super) fn validate_registration_metadata_or_response(
    state: &AppState,
    meta: &ClientRegistration,
) -> Result<(), Response> {
    validate_registration_with_config(
        meta,
        state.dcr_require_client_jwt_kid,
        &state.dcr_allowed_algs,
        &state.dcr_validation_config,
    )
    .map_err(invalid_client_metadata_response)?;
    everparse_self_check_registration_with_runtime(
        meta,
        state.dcr_validation_config.everparse_runtime_enabled(),
    )
    .map_err(|error| {
        tracing::error!(error = %error, "dcr everparse self-check failed");
        let mut response = (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "internal registration validation failed",
            })),
        )
            .into_response();
        util::apply_no_cache_headers(&mut response);
        response
    })
}

#[cfg(test)]
pub(super) fn effective_registration_metadata(
    meta: &ClientRegistration,
    existing: Option<&crate::client_registry::RegisteredClient>,
) -> ClientRegistration {
    effective_registration_metadata_with_response_types(meta, existing, None)
}

pub(super) fn effective_registration_metadata_with_response_types(
    meta: &ClientRegistration,
    existing: Option<&crate::client_registry::RegisteredClient>,
    existing_response_types: Option<&[String]>,
) -> ClientRegistration {
    let Some(existing) = existing else {
        return meta.clone();
    };

    let mut effective = meta.clone();
    effective.token_endpoint_auth_method = effective
        .token_endpoint_auth_method
        .or_else(|| Some(existing.token_endpoint_auth_method.clone()));
    effective.token_endpoint_auth_signing_alg = effective
        .token_endpoint_auth_signing_alg
        .or_else(|| existing.token_endpoint_auth_signing_alg.clone());
    effective.redirect_uris = effective
        .redirect_uris
        .or_else(|| (!existing.redirect_uris.is_empty()).then(|| existing.redirect_uris.clone()));
    effective.post_logout_redirect_uris = effective.post_logout_redirect_uris.or_else(|| {
        (!existing.post_logout_redirect_uris.is_empty())
            .then(|| existing.post_logout_redirect_uris.clone())
    });
    effective.backchannel_logout_uri = effective
        .backchannel_logout_uri
        .or_else(|| existing.backchannel_logout_uri.clone());
    effective.backchannel_logout_session_required = effective
        .backchannel_logout_session_required
        .or(Some(existing.backchannel_logout_session_required));
    effective.grant_types = effective
        .grant_types
        .or_else(|| Some(existing.allowed_grant_types.clone()));
    effective.response_types = effective.response_types.or_else(|| {
        existing_response_types
            .filter(|response_types| !response_types.is_empty())
            .map(|response_types| response_types.to_vec())
    });
    effective.scope = effective
        .scope
        .or_else(|| crate::oauth_scope::scope_string(&existing.allowed_scopes));
    effective
}
