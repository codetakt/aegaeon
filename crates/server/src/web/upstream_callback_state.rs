use super::oauth_errors::json_error_with_iss;
use super::{no_cache_redirect_response, validate_upstream_issuer, AppState};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use crate::upstream::UpstreamAuthRequest;
use crate::util;

#[derive(Deserialize, Default)]
pub(super) struct UpstreamCallbackQuery {
    state: Option<String>,
    code: Option<String>,
    iss: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub(super) struct UpstreamCallbackContext {
    pub(super) code: Option<String>,
    pub(super) request: UpstreamAuthRequest,
}

fn upstream_auth_store_unavailable_response(error: &str, issuer_base: &str) -> Response {
    tracing::error!(error = %error, "upstream authorization state store unavailable");
    json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("upstream authorization state store unavailable"),
        issuer_base,
    )
}

pub(super) fn handle_upstream_callback_error(
    params: &UpstreamCallbackQuery,
    request: &UpstreamAuthRequest,
    issuer_base: &str,
) -> Option<Response> {
    let error = params.error.as_deref()?;
    let description = params.error_description.as_deref();
    if let Some(return_to) = request.return_to.as_deref() {
        let url = util::append_error_and_state(
            return_to,
            error,
            description,
            Some(&request.state),
            issuer_base,
        );
        return Some(no_cache_redirect_response(&url));
    }
    Some(json_error_with_iss(
        StatusCode::BAD_REQUEST,
        error,
        description,
        issuer_base,
    ))
}

fn require_upstream_callback_param<'a>(
    value: Option<&'a str>,
    label: &str,
    issuer_base: &str,
) -> Result<&'a str, Response> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&format!("{label} is required")),
            issuer_base,
        )),
    }
}

pub(super) async fn consume_upstream_callback_context(
    state: &AppState,
    params: &UpstreamCallbackQuery,
    headers: &HeaderMap,
    connection: &str,
    issuer_base: &str,
) -> Result<UpstreamCallbackContext, Response> {
    let state_value =
        require_upstream_callback_param(params.state.as_deref(), "state", issuer_base)?;
    let code = if params.error.is_some() {
        None
    } else {
        Some(
            require_upstream_callback_param(params.code.as_deref(), "code", issuer_base)?
                .to_string(),
        )
    };
    let browser_digest = super::upstream_browser_binding::browser_digest(headers, state_value)
        .ok_or_else(|| {
            json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("upstream browser binding is invalid"),
                issuer_base,
            )
        })?;
    let redirect_uri =
        super::upstream_authorize::build_upstream_redirect_uri(state.base_url.as_str(), connection);
    let request = match state
        .upstream
        .auth_store
        .try_consume_bound_async(state_value.to_string(), browser_digest, redirect_uri)
        .await
    {
        Ok(Some(request)) => request,
        Ok(None) => {
            return Err(json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("state is invalid or expired"),
                issuer_base,
            ));
        }
        Err(err) => return Err(upstream_auth_store_unavailable_response(&err, issuer_base)),
    };
    Ok(UpstreamCallbackContext { code, request })
}

pub(super) fn validate_upstream_callback_issuer(
    params: &UpstreamCallbackQuery,
    request: &UpstreamAuthRequest,
    issuer_base: &str,
) -> Result<(), Response> {
    let iss = if request.require_iss_parameter {
        Some(require_upstream_callback_param(
            params.iss.as_deref(),
            "iss",
            issuer_base,
        )?)
    } else {
        params.iss.as_deref()
    };
    if let Some(iss) = iss {
        let validated = validate_upstream_issuer(iss).ok_or_else(|| {
            json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("iss is invalid"),
                issuer_base,
            )
        })?;
        if !aegaeon_pure::upstream_issuer::issuer_matches(
            request.issuer.as_bytes(),
            validated.as_bytes(),
        ) {
            return Err(json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("iss does not match"),
                issuer_base,
            ));
        }
    }
    Ok(())
}
