use super::super::oauth_errors::json_error_with_iss;
use super::super::AppState;
use super::{UpstreamAuthorizeContext, UpstreamAuthorizeInput};
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use std::time::SystemTime;
use url::Url;

use crate::oidc::OidcDiscovery;
use crate::upstream::{
    pkce_challenge, random_token, UpstreamAuthRequest, UpstreamConnectionContext,
};

pub(in crate::web) fn build_upstream_redirect_uri(base_url: &str, connection: &str) -> String {
    format!(
        "{}/oauth/upstream/{}/callback",
        base_url.trim_end_matches('/'),
        connection
    )
}

pub(super) struct UpstreamAuthorizeFlowState {
    redirect_uri: String,
    state_token: String,
    nonce: String,
    code_challenge: Option<String>,
}

pub(super) async fn store_upstream_authorize_request(
    state: &AppState,
    connection_id: &str,
    input: &UpstreamAuthorizeInput,
    context: &UpstreamAuthorizeContext,
    discovery: &OidcDiscovery,
    issuer_base: &str,
) -> Result<UpstreamAuthorizeFlowState, Response> {
    let require_pkce = context.profile.require_pkce;
    let code_verifier = require_pkce.then(|| random_token(64));
    let code_challenge = code_verifier.as_deref().map(pkce_challenge);
    let state_token = random_token(32);
    let nonce = random_token(32);
    let redirect_uri = build_upstream_redirect_uri(state.base_url.as_str(), connection_id);
    let issued_at = SystemTime::now();
    let Some(expires_at) = issued_at.checked_add(state.upstream.auth_store.ttl()) else {
        return Err(json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("upstream authorize state expiry is outside representable time"),
            issuer_base,
        ));
    };

    let stored_request = UpstreamAuthRequest {
        state: state_token.clone(),
        nonce: nonce.clone(),
        code_verifier,
        acr: input.acr.clone(),
        issuer: context.issuer.clone(),
        client_id: context.connection.client_id.clone(),
        client_secret: None,
        client_auth_method: context.auth_method.clone(),
        context: UpstreamConnectionContext::new(
            context.connection.id,
            context.connection.team_id,
            context.connection.tenant_id,
            context.connection.environment_id,
            context.connection.configuration_version_id,
        ),
        token_endpoint: discovery.token_endpoint.clone(),
        jwks_uri: discovery.jwks_uri.clone(),
        redirect_uri: redirect_uri.clone(),
        return_to: input.return_to.clone(),
        max_age: input.max_age,
        require_iss_parameter: context.profile.require_iss_parameter,
        jit_provisioning_policy: context.connection.jit_provisioning_policy.clone(),
        attribute_mappings: context.connection.attribute_mappings.clone(),
        claim_release_policy: context.connection.claim_release_policy.clone(),
        logout_policy: context.connection.logout_policy.clone(),
        issued_at,
        expires_at,
    };
    if let Err(err) = state
        .upstream
        .auth_store
        .try_insert_async(stored_request)
        .await
    {
        tracing::error!(error = %err, "upstream authorization state store insert failed");
        return Err(json_error_with_iss(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("failed to store upstream authorize state"),
            issuer_base,
        ));
    }

    Ok(UpstreamAuthorizeFlowState {
        redirect_uri,
        state_token,
        nonce,
        code_challenge,
    })
}

pub(super) fn build_upstream_authorize_redirect_response(
    issuer_base: &str,
    discovery: &OidcDiscovery,
    client_id: &str,
    input: &UpstreamAuthorizeInput,
    flow: &UpstreamAuthorizeFlowState,
    force_prompt_login: bool,
) -> Result<Response, Response> {
    let mut auth_url = Url::parse(&discovery.authorization_endpoint).map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("authorization_endpoint invalid"),
            issuer_base,
        )
    })?;
    {
        let mut pairs = auth_url.query_pairs_mut();
        pairs.append_pair("response_type", "code");
        pairs.append_pair("client_id", client_id);
        pairs.append_pair("redirect_uri", &flow.redirect_uri);
        pairs.append_pair("scope", &input.scope);
        pairs.append_pair("state", &flow.state_token);
        pairs.append_pair("nonce", &flow.nonce);
        if let Some(challenge) = flow.code_challenge.as_ref() {
            pairs.append_pair("code_challenge", challenge);
            pairs.append_pair("code_challenge_method", "S256");
        }
        if let Some(acr) = input.acr.as_ref() {
            pairs.append_pair("acr_values", acr);
        }
        if let Some(max_age) = input.max_age {
            pairs.append_pair("max_age", &max_age.to_string());
        }
        if force_prompt_login {
            pairs.append_pair("prompt", "login");
        }
    }

    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(auth_url.as_str()) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    Ok(response)
}
