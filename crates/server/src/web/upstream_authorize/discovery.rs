use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_metadata::{
    build_upstream_http_client, fetch_upstream_discovery_cached, validate_upstream_discovery,
    verify_upstream_federation_metadata_blocking,
};
use super::super::AppState;
use super::{UpstreamAuthorizeContext, UpstreamAuthorizeInput};
use axum::{http::StatusCode, response::Response};
use std::collections::HashSet;

use crate::oidc::OidcDiscovery;

fn invalidate_cached_discovery(state: &AppState, issuer: &str) {
    if let Err(err) = state.upstream.discovery_cache.try_invalidate(issuer) {
        tracing::warn!(
            error = %err,
            issuer,
            "failed to invalidate upstream discovery cache"
        );
    }
}

pub(super) async fn fetch_upstream_authorize_discovery(
    state: &AppState,
    issuer_base: &str,
    context: &UpstreamAuthorizeContext,
    input: &UpstreamAuthorizeInput,
) -> Result<OidcDiscovery, Response> {
    let allowed_domains = state.cfg.upstream().outbound_allowed_domains();
    let client = build_upstream_http_client(allowed_domains).map_err(|message| {
        json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some(&message),
            issuer_base,
        )
    })?;
    let discovery = fetch_upstream_discovery_cached(
        &client,
        &context.issuer,
        &state.upstream.discovery_cache,
        allowed_domains,
    )
    .await
    .map_err(|message| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some(&message),
            issuer_base,
        )
    })?;
    if let Err(message) = validate_upstream_discovery(
        &discovery,
        &context.issuer,
        &context.profile,
        &context.auth_method,
        allowed_domains,
    ) {
        invalidate_cached_discovery(state, &context.issuer);
        return Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some(&message),
            issuer_base,
        ));
    }
    if let Err(response) = verify_upstream_federation_metadata_blocking(
        state.clone(),
        context.issuer.clone(),
        context.connection.environment_id,
        discovery.clone(),
        None,
        issuer_base.to_string(),
    )
    .await
    {
        invalidate_cached_discovery(state, &context.issuer);
        return Err(response);
    }
    if let Some(scopes_supported) = discovery.scopes_supported.as_ref() {
        let supported: HashSet<&str> = scopes_supported.iter().map(String::as_str).collect();
        if input
            .scopes
            .iter()
            .any(|value| !supported.contains(value.as_str()))
        {
            return Err(json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                Some("requested scope not supported upstream"),
                issuer_base,
            ));
        }
    }
    if let (Some(selected_acr), Some(acr_supported)) =
        (input.acr.as_ref(), discovery.acr_values_supported.as_ref())
    {
        if !acr_supported.iter().any(|value| value == selected_acr) {
            return Err(json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("requested acr is not supported upstream"),
                issuer_base,
            ));
        }
    }
    Ok(discovery)
}
