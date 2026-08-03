use axum::{http::StatusCode, response::Response};

use crate::util;

use super::oauth_errors::no_cache_json_error_with_iss;
use super::token_response::token_error_response;

pub(super) struct TokenForm {
    pub(super) grant_type: String,
    pub(super) code: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) code_verifier: Option<String>,
    pub(super) redirect_uri: Option<String>,
    pub(super) scope: Option<String>,
    pub(super) refresh_token: Option<String>,
    pub(super) assertion: Option<String>,
    pub(super) client_assertion_type: Option<String>,
    pub(super) client_assertion: Option<String>,
    /// RFC 8628: `device_code` for the device authorization grant.
    pub(super) device_code: Option<String>,
}

fn token_param(
    params: &[(String, String)],
    key: &str,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    let mut value: Option<String> = None;
    for (param_key, param_value) in params {
        if param_key != key {
            continue;
        }
        if value.is_some() {
            let description = format!("{key} must not be specified multiple times");
            return Err(no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(&description),
                issuer_base,
            ));
        }
        value = Some(param_value.clone());
    }
    Ok(value)
}

fn missing_required_token_param_error(key: &str, issuer_base: &str) -> Response {
    let description = format!("{key} is required");
    no_cache_json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some(&description),
        issuer_base,
    )
}

pub(super) fn optional_token_param(
    params: &[(String, String)],
    key: &str,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    token_param(params, key, issuer_base)
}

pub(super) fn required_token_param(
    params: &[(String, String)],
    key: &str,
    issuer_base: &str,
) -> Result<String, Response> {
    token_param(params, key, issuer_base)?
        .ok_or_else(|| missing_required_token_param_error(key, issuer_base))
}

pub(super) fn token_form_from_params(
    params: &[(String, String)],
    issuer_base: &str,
) -> Result<TokenForm, Response> {
    Ok(TokenForm {
        grant_type: required_token_param(params, "grant_type", issuer_base)?,
        code: optional_token_param(params, "code", issuer_base)?,
        client_id: optional_token_param(params, "client_id", issuer_base)?,
        client_secret: optional_token_param(params, "client_secret", issuer_base)?,
        code_verifier: optional_token_param(params, "code_verifier", issuer_base)?,
        redirect_uri: optional_token_param(params, "redirect_uri", issuer_base)?,
        scope: optional_token_param(params, "scope", issuer_base)?,
        refresh_token: optional_token_param(params, "refresh_token", issuer_base)?,
        assertion: optional_token_param(params, "assertion", issuer_base)?,
        client_assertion_type: optional_token_param(params, "client_assertion_type", issuer_base)?,
        client_assertion: optional_token_param(params, "client_assertion", issuer_base)?,
        device_code: optional_token_param(params, "device_code", issuer_base)?,
    })
}

pub(super) fn token_resource_from_params(
    params: &[(String, String)],
) -> Result<Option<String>, Response> {
    let resources = params
        .iter()
        .filter(|(key, _)| key == "resource")
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    util::parse_single_resource_indicator(&resources).map_err(|description| {
        token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some(&description),
        )
    })
}
