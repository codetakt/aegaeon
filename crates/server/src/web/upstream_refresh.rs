use super::oauth_errors::json_error_with_iss;
use super::request_admission::enforce_no_credentials_in_uri;
use super::upstream_id_token::{
    refreshed_upstream_id_token_signature_failure, validate_upstream_id_token,
    verify_upstream_id_token_claims, UpstreamIdTokenValidationInput,
};
use super::upstream_metadata::{
    fetch_upstream_jwks_cached, verify_upstream_federation_metadata_blocking,
};
use super::upstream_refresh_links::{
    authenticate_upstream_refresh_caller, load_upstream_refresh_link, UpstreamRefreshLink,
    UpstreamRefreshQuery,
};
use super::upstream_refresh_token_envelope::{
    seal_upstream_refresh_token, upstream_refresh_token_envelope_error_response,
};
use super::upstream_token_response::UpstreamTokenResponse;
use super::{transport_rejection, AppState};
use axum::{
    extract::{ConnectInfo, OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sqlx::PgPool;
use std::net::SocketAddr;

use crate::oidc::IdToken;
use crate::util;

mod exchange;
mod profile;
use exchange::{perform_upstream_refresh_exchange, UpstreamRefreshExchange};
use profile::resolve_upstream_refresh_profile;
#[cfg(test)]
pub(super) use profile::validate_upstream_refresh_profile_policy;

fn next_upstream_refresh_generation(current: i64, issuer_base: &str) -> Result<i64, Response> {
    current.checked_add(1).ok_or_else(|| {
        json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("upstream refresh token generation overflow"),
            issuer_base,
        )
    })
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
    let jwks = fetch_upstream_jwks_cached(
        &exchange.client,
        &exchange.discovery.jwks_uri,
        &state.upstream.jwks_cache,
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
    .map_err(|error| {
        tracing::warn!(
            upstream_issuer = %link.upstream_issuer,
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

async fn persist_upstream_refresh_exchange(
    pool: &PgPool,
    link: &UpstreamRefreshLink,
    token_response: &UpstreamTokenResponse,
    issuer_base: &str,
) -> Result<(), Response> {
    if let Some(new_refresh_token) = token_response.refresh_token.as_ref() {
        let next_generation =
            next_upstream_refresh_generation(link.upstream_refresh_token_generation, issuer_base)?;
        let encrypted_refresh_token = seal_upstream_refresh_token(
            new_refresh_token,
            link.link_env_id,
            link.upstream_issuer.as_str(),
            link.upstream_sub_hash.as_str(),
            link.upstream_connection_id,
            next_generation,
        )
        .map_err(|error| {
            upstream_refresh_token_envelope_error_response(
                error,
                "failed to encrypt rotated upstream refresh token",
                issuer_base,
            )
        })?;
        let result = sqlx::query(
            "UPDATE aegaeon.account_links \
             SET upstream_refresh_token_encrypted = $1, \
                 upstream_refresh_token_connection_id = $2, \
                 upstream_refresh_token_generation = $3, \
                 last_used_at = now() \
             WHERE id = $4 \
               AND environment_id = $5 \
               AND upstream_issuer = $6 \
               AND upstream_sub_hash = $7 \
               AND connection_id = $2 \
               AND upstream_refresh_token_connection_id = $2 \
               AND upstream_refresh_token_generation = $8",
        )
        .bind(encrypted_refresh_token)
        .bind(link.upstream_connection_id)
        .bind(next_generation)
        .bind(link.account_link_id)
        .bind(link.link_env_id)
        .bind(&link.upstream_issuer)
        .bind(&link.upstream_sub_hash)
        .bind(link.upstream_refresh_token_generation)
        .execute(pool)
        .await
        .map_err(|_| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some("failed to persist rotated upstream refresh token"),
                issuer_base,
            )
        })?;
        if result.rows_affected() == 0 {
            return Err(json_error_with_iss(
                StatusCode::CONFLICT,
                "invalid_grant",
                Some("upstream refresh token generation is stale"),
                issuer_base,
            ));
        }
        return Ok(());
    }
    let result = sqlx::query(
        "UPDATE aegaeon.account_links SET last_used_at = now() \
         WHERE id = $1 \
           AND environment_id = $2 \
           AND upstream_issuer = $3 \
           AND upstream_sub_hash = $4 \
           AND connection_id = $5 \
           AND upstream_refresh_token_connection_id = $5 \
           AND upstream_refresh_token_generation = $6",
    )
    .bind(link.account_link_id)
    .bind(link.link_env_id)
    .bind(&link.upstream_issuer)
    .bind(&link.upstream_sub_hash)
    .bind(link.upstream_connection_id)
    .bind(link.upstream_refresh_token_generation)
    .execute(pool)
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to persist upstream refresh metadata"),
            issuer_base,
        )
    })?;
    if result.rows_affected() == 0 {
        return Err(json_error_with_iss(
            StatusCode::CONFLICT,
            "invalid_grant",
            Some("upstream refresh token generation is stale"),
            issuer_base,
        ));
    }
    Ok(())
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
        return transport_rejection(&state, kind);
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
    if let Err(resp) =
        persist_upstream_refresh_exchange(pool, &link, &exchange.token_response, issuer_base).await
    {
        return resp;
    }
    build_upstream_refresh_response(&link, &exchange.token_response)
}
