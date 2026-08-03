use super::oauth_errors::json_error_with_iss;
use super::upstream_id_token::{decode_upstream_id_token, UpstreamIdTokenDecodeInput};
use super::upstream_metadata::{
    build_upstream_http_client, fetch_upstream_discovery_cached, fetch_upstream_jwks_cached,
    validate_upstream_outbound_url, verify_upstream_federation_metadata_blocking,
};
use super::upstream_token_response::{
    parse_upstream_token_response_body, validate_upstream_authorization_code_token_response_shape,
    UpstreamTokenResponse, UpstreamTokenResponseContext,
};
use super::{normalize_issuer, AppState, UPSTREAM_MAX_BODY_BYTES};
use aegaeon_jose::jwk::JwkSet;
use axum::{http::StatusCode, response::Response};
use reqwest::Client;

use crate::oidc::{IdToken, OidcDiscovery};
use crate::upstream::{upstream_subject_link_hash, UpstreamAuthRequest};

pub(super) struct UpstreamCallbackExchange {
    pub(super) discovery: OidcDiscovery,
    pub(super) token_response: UpstreamTokenResponse,
    pub(super) id_token: IdToken,
    pub(super) upstream_sub_hash: String,
}

async fn fetch_upstream_callback_discovery(
    state: &AppState,
    request: &UpstreamAuthRequest,
    issuer_base: &str,
) -> Result<(Client, OidcDiscovery), Response> {
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
        &request.issuer,
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
    let normalized_issuer = normalize_issuer(&discovery.issuer).ok_or_else(|| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("upstream discovery issuer invalid"),
            issuer_base,
        )
    })?;
    if normalized_issuer != request.issuer
        || discovery.token_endpoint != request.token_endpoint
        || discovery.jwks_uri != request.jwks_uri
    {
        return Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("upstream metadata changed"),
            issuer_base,
        ));
    }
    Ok((client, discovery))
}

async fn exchange_upstream_callback_token(
    client: &Client,
    request: &UpstreamAuthRequest,
    code: &str,
    issuer_base: &str,
    allowed_domains: &[String],
) -> Result<UpstreamTokenResponse, Response> {
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", request.redirect_uri.clone()),
    ];
    match request.client_auth_method.as_str() {
        "client_secret_post" => {
            form.push(("client_id", request.client_id.clone()));
            if let Some(secret) = request.client_secret.as_ref() {
                form.push(("client_secret", secret.clone()));
            }
        }
        "client_secret_basic" => {}
        _ => {
            form.push(("client_id", request.client_id.clone()));
        }
    }
    if let Some(verifier) = request.code_verifier.as_deref() {
        form.push(("code_verifier", verifier.to_string()));
    }
    validate_upstream_outbound_url(
        &request.token_endpoint,
        "upstream token_endpoint",
        allowed_domains,
    )
    .map_err(|message| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some(&message),
            issuer_base,
        )
    })?;
    let mut token_req = client.post(&request.token_endpoint).form(&form);
    if request.client_auth_method == "client_secret_basic" {
        if let Some(secret) = request.client_secret.as_ref() {
            token_req = token_req.basic_auth(&request.client_id, Some(secret));
        }
    }
    let token_response = token_req.send().await.map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to call upstream token endpoint"),
            issuer_base,
        )
    })?;
    if !token_response.status().is_success() {
        return Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("upstream token endpoint returned error"),
            issuer_base,
        ));
    }
    let body =
        crate::outbound_http::read_response_body_limited(token_response, UPSTREAM_MAX_BODY_BYTES)
            .await
            .map_err(|err| {
                let message = match err {
                    crate::outbound_http::BoundedBodyError::TooLarge { .. } => {
                        "upstream token response too large".to_string()
                    }
                    other => format!("failed to read upstream token response: {other}"),
                };
                json_error_with_iss(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    Some(&message),
                    issuer_base,
                )
            })?;
    parse_upstream_token_response_body(&body, issuer_base, "upstream token response invalid")
}

async fn verify_upstream_callback_federation(
    state: &AppState,
    request: &UpstreamAuthRequest,
    discovery: &OidcDiscovery,
    jwks: &JwkSet,
    issuer_base: &str,
) -> Result<(), Response> {
    verify_upstream_federation_metadata_blocking(
        state.clone(),
        request.issuer.clone(),
        request.managed_connection_context().environment_id,
        discovery.clone(),
        Some(jwks.clone()),
        issuer_base.to_string(),
    )
    .await
}

pub(super) async fn perform_upstream_callback_exchange(
    state: &AppState,
    request: &UpstreamAuthRequest,
    code: &str,
    issuer_base: &str,
) -> Result<UpstreamCallbackExchange, Response> {
    let (client, discovery) =
        fetch_upstream_callback_discovery(state, request, issuer_base).await?;
    let allowed_domains = state.cfg.upstream().outbound_allowed_domains();
    let token_response =
        exchange_upstream_callback_token(&client, request, code, issuer_base, allowed_domains)
            .await?;
    validate_upstream_authorization_code_token_response_shape(&token_response).map_err(|err| {
        let message = err.message(UpstreamTokenResponseContext::AuthorizationCode);
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some(&message),
            issuer_base,
        )
    })?;
    let Some(id_token_str) = token_response.id_token.as_deref() else {
        return Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("upstream token response missing id_token"),
            issuer_base,
        ));
    };
    let jwks = fetch_upstream_jwks_cached(
        &client,
        &request.jwks_uri,
        &state.upstream.jwks_cache,
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
    verify_upstream_callback_federation(state, request, &discovery, &jwks, issuer_base).await?;
    let id_token = decode_upstream_id_token(UpstreamIdTokenDecodeInput {
        token: id_token_str,
        jwks: &jwks,
        discovery: &discovery,
        request,
        access_token: token_response.access_token.as_deref(),
        code,
        jwt_leeway_secs: state.cfg.jwt_runtime().leeway_secs(),
        jose_header_max_len: state.cfg.jose_header_max_len,
    })
    .map_err(|error| {
        json_error_with_iss(
            error.status,
            "server_error",
            Some(&error.message),
            issuer_base,
        )
    })?;
    Ok(UpstreamCallbackExchange {
        discovery,
        upstream_sub_hash: upstream_subject_link_hash(&request.issuer, &id_token.claims.sub),
        token_response,
        id_token,
    })
}
