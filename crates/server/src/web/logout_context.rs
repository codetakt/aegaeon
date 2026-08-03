use super::logout_id_token_hint::{client_id_from_id_token_hint, decode_id_token_hint};
use super::oauth_errors::{no_cache_json_error_with_iss, registry_state_error_response};
use super::AppState;
use axum::{http::StatusCode, response::Response};
use serde::Deserialize;

use crate::oidc::{IdTokenClaims, OidcConfig, OidcLogoutEvent};

#[derive(Deserialize, Default)]
pub(super) struct LogoutQuery {
    pub(super) id_token_hint: Option<String>,
    pub(super) post_logout_redirect_uri: Option<String>,
    pub(super) state: Option<String>,
}

pub(super) struct LogoutContext {
    pub(super) client_id: String,
    claims: IdTokenClaims,
}

fn oidc_session_store_error_response(issuer_base: &str, error: &str) -> Response {
    tracing::error!(error, "OIDC session store operation failed during logout");
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("failed to update OIDC logout session"),
        issuer_base,
    )
}

pub(super) async fn logout_events_from_context(
    state: &AppState,
    context: &LogoutContext,
    issuer_base: &str,
) -> Result<Vec<OidcLogoutEvent>, Response> {
    let Some(sessions) = state.oidc.sessions.as_ref() else {
        return Ok(Vec::new());
    };
    let claims = &context.claims;
    let sid = claims.sid.as_deref().unwrap_or("");
    if !sid.trim().is_empty() {
        return sessions
            .try_logout_by_sid_async(sid.to_string())
            .await
            .map(|event| event.into_iter().collect())
            .map_err(|err| oidc_session_store_error_response(issuer_base, &err));
    }
    if !claims.sub.trim().is_empty() {
        return sessions
            .try_logout_by_user_async(claims.sub.clone())
            .await
            .map_err(|err| oidc_session_store_error_response(issuer_base, &err));
    }
    Ok(Vec::new())
}

pub(super) fn resolve_logout_context(
    state: &AppState,
    cfg: &OidcConfig,
    query: &LogoutQuery,
    issuer_base: &str,
) -> Result<Option<LogoutContext>, Response> {
    if query.id_token_hint.is_none() && query.post_logout_redirect_uri.is_some() {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("id_token_hint is required when post_logout_redirect_uri is provided"),
            issuer_base,
        ));
    }

    let Some(id_token_hint) = query.id_token_hint.as_deref() else {
        return Ok(None);
    };
    let claims = decode_id_token_hint(cfg, id_token_hint, state.cfg.jose_header_max_len).map_err(
        |error| {
            no_cache_json_error_with_iss(
                error.status,
                error.error,
                Some(error.public_description()),
                issuer_base,
            )
        },
    )?;
    let client_id = client_id_from_id_token_hint(&claims).map_err(|description| {
        no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&description),
            issuer_base,
        )
    })?;
    if state
        .clients
        .try_get(&client_id)
        .map_err(|error| registry_state_error_response(issuer_base, "logout_get_client", error))?
        .is_none()
    {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("client is not registered"),
            issuer_base,
        ));
    }

    Ok(Some(LogoutContext { client_id, claims }))
}

pub(super) fn validate_post_logout_redirect_uri(
    state: &AppState,
    client_id: &str,
    query: &LogoutQuery,
    issuer_base: &str,
) -> Result<(), Response> {
    if let Some(post_logout_redirect_uri) = query.post_logout_redirect_uri.as_deref() {
        let redirect_uri_valid = state
            .clients
            .try_validate_post_logout_redirect_uri(client_id, post_logout_redirect_uri)
            .map_err(|error| {
                registry_state_error_response(
                    issuer_base,
                    "logout_validate_post_logout_redirect_uri",
                    error,
                )
            })?;
        if !redirect_uri_valid {
            return Err(no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("post_logout_redirect_uri is not registered"),
                issuer_base,
            ));
        }
    }

    Ok(())
}
