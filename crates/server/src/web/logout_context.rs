use super::logout_id_token_hint::{client_id_from_id_token_hint, decode_id_token_hint};
use super::oauth_errors::{no_cache_json_error_with_iss, registry_state_error_response};
use super::AppState;
use axum::{http::StatusCode, response::Response};
use serde::{Deserialize, Serialize};

use crate::oidc::OidcConfig;

#[derive(Clone, Deserialize, Serialize, Default)]
pub(super) struct LogoutQuery {
    pub(super) client_id: Option<String>,
    pub(super) id_token_hint: Option<String>,
    pub(super) post_logout_redirect_uri: Option<String>,
    pub(super) state: Option<String>,
}

pub(super) struct LogoutContext {
    pub(super) client_id: String,
}

pub(super) fn resolve_logout_context(
    state: &AppState,
    cfg: &OidcConfig,
    query: &LogoutQuery,
    issuer_base: &str,
) -> Result<Option<LogoutContext>, Response> {
    let hinted_client = query
        .id_token_hint
        .as_deref()
        .map(|token| {
            let claims = decode_id_token_hint(cfg, token, state.cfg.jose_header_max_len).map_err(
                |error| {
                    no_cache_json_error_with_iss(
                        error.status,
                        error.error,
                        Some(error.public_description()),
                        issuer_base,
                    )
                },
            )?;
            client_id_from_id_token_hint(&claims).map_err(|description| {
                no_cache_json_error_with_iss(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some(&description),
                    issuer_base,
                )
            })
        })
        .transpose()?;
    if matches!((&query.client_id, &hinted_client), (Some(explicit), Some(hinted)) if explicit != hinted)
    {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("client_id does not match id_token_hint"),
            issuer_base,
        ));
    }
    let Some(client_id) = hinted_client.or_else(|| query.client_id.clone()) else {
        if query.post_logout_redirect_uri.is_some() {
            return Err(no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("a client identity is required for post_logout_redirect_uri"),
                issuer_base,
            ));
        }
        return Ok(None);
    };
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

    Ok(Some(LogoutContext { client_id }))
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
