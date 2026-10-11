use super::oauth_errors::no_cache_json_error_with_iss as json_error_with_iss;
use super::request_admission::enforce_no_credentials_in_uri;
use super::transport_boundary::transport_rejection_for_route;
use super::upstream_id_token::{
    admit_upstream_id_token_header, refreshed_upstream_id_token_signature_failure,
    validate_upstream_id_token, verify_upstream_id_token_claims, UpstreamIdTokenValidationInput,
};
use super::upstream_metadata::{
    fetch_upstream_jwks_cached, verify_upstream_federation_metadata_blocking,
};
use super::upstream_refresh_links::{
    authenticate_upstream_refresh_caller, load_upstream_refresh_link, UpstreamRefreshLink,
    UpstreamRefreshQuery,
};
use super::upstream_token_response::UpstreamTokenResponse;
use super::AppState;
use axum::{
    extract::{ConnectInfo, OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

use crate::oidc::IdToken;
use crate::util;

mod exchange;
mod persistence;
mod profile;
mod runtime_version;
use aegaeon_pure::upstream_refresh as freshness;
use exchange::{perform_upstream_refresh_exchange, UpstreamRefreshExchange};
use persistence::persist_upstream_refresh_exchange;
use profile::resolve_upstream_refresh_profile;
#[cfg(test)]
pub(super) use profile::validate_upstream_refresh_profile_policy;

async fn fetch_upstream_refresh_jwks(
    state: &AppState,
    link: &UpstreamRefreshLink,
    issuer_base: &str,
    exchange: &UpstreamRefreshExchange,
    id_token_str: &str,
) -> Result<aegaeon_jose::jwk::JwkSet, Response> {
    let header = admit_upstream_id_token_header(
        id_token_str,
        &exchange.discovery,
        state.cfg.jose_header_max_len,
    )
    .map_err(refreshed_upstream_id_token_signature_failure)
    .map_err(|error| {
        json_error_with_iss(
            error.status,
            "server_error",
            Some(&error.message),
            issuer_base,
        )
    })?;
    let jwks = fetch_upstream_jwks_cached(
        &exchange.client,
        &exchange.discovery.jwks_uri,
        &state.upstream.jwks_cache,
        &state.upstream.jwks_fetches,
        &header,
        state.cfg.upstream().outbound_allowed_domains(),
        |candidate| async move {
            verify_upstream_federation_metadata_blocking(
                state.clone(),
                link.upstream_issuer.clone(),
                link.link_env_id,
                exchange.discovery.clone(),
                Some(candidate),
                issuer_base.to_string(),
            )
            .await
            .map_err(|_| "upstream JWKS does not match federation metadata".to_string())
        },
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
    Ok(jwks)
}

async fn validate_upstream_refresh_exchange(
    state: &AppState,
    issuer_base: &str,
    link: &UpstreamRefreshLink,
    exchange: &UpstreamRefreshExchange,
) -> Result<(), Response> {
    let Some(id_token_str) = exchange.token_response.id_token.as_ref() else {
        return Ok(());
    };
    let jwks =
        fetch_upstream_refresh_jwks(state, link, issuer_base, exchange, id_token_str).await?;
    verify_upstream_federation_metadata_blocking(
        state.clone(),
        link.upstream_issuer.clone(),
        link.link_env_id,
        exchange.discovery.clone(),
        Some(jwks.clone()),
        issuer_base.to_string(),
    )
    .await?;
    let (claims, alg_name) = verify_upstream_id_token_claims(
        id_token_str,
        &jwks,
        &exchange.discovery,
        state.cfg.jose_header_max_len,
    )
    .map_err(|error| {
        let failure = refreshed_upstream_id_token_signature_failure(error);
        json_error_with_iss(
            failure.status,
            "server_error",
            Some(&failure.message),
            issuer_base,
        )
    })?;
    let id_token = IdToken {
        claims,
        signing_alg: alg_name.to_string(),
    };
    validate_upstream_id_token(
        &id_token,
        &UpstreamIdTokenValidationInput {
            client_id: &link.upstream_client_id,
            issuer: &link.upstream_issuer,
            expected_nonce: None,
            max_age: None,
            access_token: exchange.token_response.access_token.as_deref(),
            code: None,
            requested_acr: None,
            jwt_leeway_secs: state.cfg.jwt_runtime().leeway_secs(),
        },
    )
    .and_then(|()| {
        if !freshness::issued_during_refresh(
            id_token.claims.iat,
            exchange.request_started_at,
            state.cfg.jwt_runtime().leeway_secs(),
        ) {
            return Err("refreshed id_token predates refresh request".to_string());
        }
        link.original_authentication
            .validate_refreshed_id_token(&id_token)
            .map_err(|_| "original authentication context mismatch".to_string())
    })
    .map_err(|error| {
        tracing::warn!(
            error = %error,
            "upstream refreshed id_token validation failed"
        );
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("upstream refreshed id_token claims invalid"),
            issuer_base,
        )
    })
}

fn build_upstream_refresh_response(
    link: &UpstreamRefreshLink,
    token_response: &UpstreamTokenResponse,
) -> Response {
    let mut response_body = json!({
        "upstream_issuer": link.upstream_issuer,
        "token_type": token_response.token_type.as_deref().unwrap_or("Bearer"),
    });
    if let Some(access_token) = token_response.access_token.as_ref() {
        response_body["upstream_access_token"] = json!(access_token);
    }
    if let Some(id_token) = token_response.id_token.as_ref() {
        response_body["upstream_id_token"] = json!(id_token);
    }
    if let Some(expires_in) = token_response.expires_in {
        response_body["expires_in"] = json!(expires_in);
    }
    if token_response.refresh_token.is_some() {
        response_body["refresh_token_rotated"] = json!(true);
    }

    let mut response = (StatusCode::OK, Json(response_body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) async fn upstream_refresh(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(query): Query<UpstreamRefreshQuery>,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection_for_route(&state, kind, uri.path());
    }
    if let Err(resp) = enforce_no_credentials_in_uri(&uri, issuer_base) {
        return resp;
    }
    let caller =
        match authenticate_upstream_refresh_caller(&state, &uri, &headers, issuer_base).await {
            Ok(caller) => caller,
            Err(resp) => return resp,
        };
    let pool = &state.db_pool;
    let link = match load_upstream_refresh_link(
        pool,
        &caller,
        query.upstream_issuer.as_deref(),
        issuer_base,
    )
    .await
    {
        Ok(link) => link,
        Err(resp) => return resp,
    };
    if let Err(response) =
        runtime_version::validate_loaded_runtime_version(&state, &link, issuer_base)
    {
        return response;
    }
    let profile = match resolve_upstream_refresh_profile(&state, issuer_base, &link).await {
        Ok(profile) => profile,
        Err(resp) => return resp,
    };
    let exchange =
        match perform_upstream_refresh_exchange(&state, issuer_base, &link, &profile).await {
            Ok(exchange) => exchange,
            Err(resp) => return resp,
        };
    if let Err(resp) =
        validate_upstream_refresh_exchange(&state, issuer_base, &link, &exchange).await
    {
        return resp;
    }
    if let Err(resp) = persist_upstream_refresh_exchange(
        pool,
        &link,
        &exchange.token_response,
        &profile,
        issuer_base,
    )
    .await
    {
        return resp;
    }
    build_upstream_refresh_response(&link, &exchange.token_response)
}

#[cfg(test)]
mod tests;
