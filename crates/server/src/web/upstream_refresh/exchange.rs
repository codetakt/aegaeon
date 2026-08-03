use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_metadata::{
    build_upstream_http_client, fetch_upstream_discovery_cached, validate_upstream_discovery,
    validate_upstream_outbound_url, verify_upstream_federation_metadata_blocking,
};
use super::super::upstream_refresh_links::UpstreamRefreshLink;
use super::super::upstream_token_response::{
    parse_upstream_token_response_body, validate_upstream_refresh_token_response_shape,
    UpstreamTokenResponse, UpstreamTokenResponseContext,
};
use super::super::{AppState, UPSTREAM_MAX_BODY_BYTES};
use crate::oauth_profile;
use crate::oidc::OidcDiscovery;
use crate::upstream::upstream_client_auth_method_supported;
use axum::response::Response;
use http::StatusCode;
use reqwest::{Client, RequestBuilder, Response as ReqwestResponse};

pub(super) struct UpstreamRefreshExchange {
    pub(super) client: Client,
    pub(super) discovery: OidcDiscovery,
    pub(super) token_response: UpstreamTokenResponse,
}

fn upstream_exchange_error(status: StatusCode, issuer_base: &str, message: &str) -> Response {
    json_error_with_iss(status, "server_error", Some(message), issuer_base)
}

fn build_refresh_http_client(
    issuer_base: &str,
    allowed_domains: &[String],
) -> Result<Client, Response> {
    build_upstream_http_client(allowed_domains).map_err(|message| {
        json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some(&message),
            issuer_base,
        )
    })
}

fn invalidate_cached_discovery(state: &AppState, issuer: &str) {
    if let Err(err) = state.upstream.discovery_cache.try_invalidate(issuer) {
        tracing::warn!(
            error = %err,
            issuer,
            "failed to invalidate upstream discovery cache"
        );
    }
}

async fn fetch_verified_discovery(
    state: &AppState,
    client: &Client,
    link: &UpstreamRefreshLink,
    profile: &oauth_profile::ResolvedProfile,
    auth_method: &str,
    issuer_base: &str,
) -> Result<OidcDiscovery, Response> {
    let discovery = fetch_upstream_discovery_cached(
        client,
        &link.upstream_issuer,
        &state.upstream.discovery_cache,
        state.cfg.upstream().outbound_allowed_domains(),
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
        &link.upstream_issuer,
        profile,
        auth_method,
        state.cfg.upstream().outbound_allowed_domains(),
    ) {
        invalidate_cached_discovery(state, &link.upstream_issuer);
        return Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some(&message),
            issuer_base,
        ));
    }

    if let Err(response) = verify_upstream_federation_metadata_blocking(
        state.clone(),
        link.upstream_issuer.clone(),
        link.link_env_id,
        discovery.clone(),
        None,
        issuer_base.to_string(),
    )
    .await
    {
        invalidate_cached_discovery(state, &link.upstream_issuer);
        return Err(response);
    }
    Ok(discovery)
}

fn resolve_refresh_auth_method(
    link: &UpstreamRefreshLink,
    issuer_base: &str,
) -> Result<String, Response> {
    let auth_method = link.upstream_auth_method.to_ascii_lowercase();
    if !upstream_client_auth_method_supported(&auth_method) {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("unsupported client_auth_method"),
            issuer_base,
        ));
    }
    Ok(auth_method)
}

fn build_refresh_form(
    link: &UpstreamRefreshLink,
    auth_method: &str,
) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", link.upstream_refresh_token.clone()),
    ];
    match auth_method {
        "client_secret_post" => {
            form.push(("client_id", link.upstream_client_id.clone()));
            if let Some(secret) = link.upstream_client_secret.as_ref() {
                form.push(("client_secret", secret.clone()));
            }
        }
        "client_secret_basic" => {}
        _ => {
            form.push(("client_id", link.upstream_client_id.clone()));
        }
    }
    form
}

fn build_refresh_token_request(
    client: &Client,
    discovery: &OidcDiscovery,
    link: &UpstreamRefreshLink,
    auth_method: &str,
    form: &[(&'static str, String)],
) -> RequestBuilder {
    let mut token_req = client.post(&discovery.token_endpoint).form(form);
    if auth_method == "client_secret_basic" {
        if let Some(secret) = link.upstream_client_secret.as_ref() {
            token_req = token_req.basic_auth(&link.upstream_client_id, Some(secret));
        }
    }
    token_req
}

async fn send_refresh_token_request(
    token_req: RequestBuilder,
    link: &UpstreamRefreshLink,
    issuer_base: &str,
) -> Result<ReqwestResponse, Response> {
    let token_response = token_req.send().await.map_err(|_| {
        upstream_exchange_error(
            StatusCode::BAD_GATEWAY,
            issuer_base,
            "failed to call upstream token endpoint for refresh",
        )
    })?;
    if !token_response.status().is_success() {
        tracing::warn!(
            upstream_issuer = %link.upstream_issuer,
            upstream_status = %token_response.status(),
            "upstream token refresh failed"
        );
        return Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("upstream token refresh failed"),
            issuer_base,
        ));
    }
    Ok(token_response)
}

async fn read_refresh_token_response_body(
    token_response: ReqwestResponse,
    issuer_base: &str,
) -> Result<Vec<u8>, Response> {
    crate::outbound_http::read_response_body_limited(token_response, UPSTREAM_MAX_BODY_BYTES)
        .await
        .map_err(|err| {
            let message = match err {
                crate::outbound_http::BoundedBodyError::TooLarge { .. } => {
                    "upstream refresh response too large".to_string()
                }
                other => format!("failed to read upstream refresh response: {other}"),
            };
            upstream_exchange_error(StatusCode::BAD_GATEWAY, issuer_base, &message)
        })
}

fn parse_validated_refresh_response(
    body: &[u8],
    issuer_base: &str,
) -> Result<UpstreamTokenResponse, Response> {
    let token_response =
        parse_upstream_token_response_body(body, issuer_base, "upstream refresh response invalid")?;
    validate_upstream_refresh_token_response_shape(&token_response).map_err(|err| {
        let message = err.message(UpstreamTokenResponseContext::RefreshToken);
        upstream_exchange_error(StatusCode::BAD_GATEWAY, issuer_base, &message)
    })?;
    Ok(token_response)
}

pub(super) async fn perform_upstream_refresh_exchange(
    state: &AppState,
    issuer_base: &str,
    link: &UpstreamRefreshLink,
    profile: &oauth_profile::ResolvedProfile,
) -> Result<UpstreamRefreshExchange, Response> {
    let allowed_domains = state.cfg.upstream().outbound_allowed_domains();
    let client = build_refresh_http_client(issuer_base, allowed_domains)?;
    let auth_method = resolve_refresh_auth_method(link, issuer_base)?;
    let discovery =
        fetch_verified_discovery(state, &client, link, profile, &auth_method, issuer_base).await?;
    let form = build_refresh_form(link, &auth_method);
    validate_upstream_outbound_url(&discovery.token_endpoint, "token_endpoint", allowed_domains)
        .map_err(|message| {
            upstream_exchange_error(StatusCode::BAD_GATEWAY, issuer_base, &message)
        })?;
    let token_req = build_refresh_token_request(&client, &discovery, link, &auth_method, &form);
    let upstream_response = send_refresh_token_request(token_req, link, issuer_base).await?;
    let body = read_refresh_token_response_body(upstream_response, issuer_base).await?;
    let token_response = parse_validated_refresh_response(&body, issuer_base)?;

    Ok(UpstreamRefreshExchange {
        client,
        discovery,
        token_response,
    })
}
