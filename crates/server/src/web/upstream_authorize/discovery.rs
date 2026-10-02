use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_metadata::{
    build_upstream_http_client, fetch_upstream_discovery_cached, resolve_upstream_metadata_with,
    validate_upstream_discovery,
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

// Request construction is currently a plain code-flow authorization request.
// Keep this capability check out of shared callback/refresh validation.
fn validate_request_modes(
    state: &AppState,
    issuer_base: &str,
    issuer: &str,
    discovery: &OidcDiscovery,
) -> Result<(), Response> {
    let description = if discovery.require_pushed_authorization_requests == Some(true) {
        Some("upstream requires pushed authorization requests")
    } else if discovery.require_signed_request_object == Some(true) {
        Some("upstream requires signed request objects")
    } else {
        None
    };
    if let Some(description) = description {
        invalidate_cached_discovery(state, issuer);
        return Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some(description),
            issuer_base,
        ));
    }
    Ok(())
}

pub(in crate::web) async fn fetch_upstream_authorize_discovery_with<F, Fut>(
    state: &AppState,
    issuer_base: &str,
    context: &UpstreamAuthorizeContext,
    input: &UpstreamAuthorizeInput,
    acquire: F,
) -> Result<OidcDiscovery, Response>
where
    F: FnMut(Vec<crate::federation::TrustAnchor>, i64) -> Fut,
    Fut: std::future::Future<
        Output = Result<crate::federation::ResolvedTrustChain, crate::federation::FederationError>,
    >,
{
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
    validate_request_modes(state, issuer_base, &context.issuer, &discovery)?;
    let discovery = resolve_upstream_metadata_with(
        state,
        &context.issuer,
        context.connection.environment_id,
        discovery,
        issuer_base,
        acquire,
    )
    .await
    .inspect_err(|_| invalidate_cached_discovery(state, &context.issuer))?
    .discovery;
    validate_request_modes(state, issuer_base, &context.issuer, &discovery)?;
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
