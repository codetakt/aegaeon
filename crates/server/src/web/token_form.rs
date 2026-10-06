use axum::{http::StatusCode, response::Response};

use crate::util;

use super::oauth_errors::no_cache_json_error_with_iss;
use super::token_response::token_error_response;

/// Apply RFC 6749 omission semantics after transport/body admission. Nonempty
/// decoded values (including whitespace) and repeated extension values stay exact.
/// Callers must enforce any raw byte/count limits before this operation.
pub(super) fn effective_oauth_form(mut params: Vec<(String, String)>) -> Vec<(String, String)> {
    params.retain(|(_, value)| !value.is_empty());
    params
}

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
    omit_empty: bool,
) -> Result<Option<String>, Response> {
    let mut value: Option<String> = None;
    for (param_key, param_value) in params {
        if param_key != key || (omit_empty && param_value.is_empty()) {
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
    token_param(params, key, issuer_base, false)
}

pub(super) fn required_token_param(
    params: &[(String, String)],
    key: &str,
    issuer_base: &str,
) -> Result<String, Response> {
    token_param(params, key, issuer_base, false)?
        .ok_or_else(|| missing_required_token_param_error(key, issuer_base))
}

// Token endpoint omission must not change shared device-authorization helpers.
fn effective_token_param(
    params: &[(String, String)],
    key: &str,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    token_param(params, key, issuer_base, true)
}

pub(super) fn token_form_from_params(
    params: &[(String, String)],
    issuer_base: &str,
) -> Result<TokenForm, Response> {
    // RFC 6749 §3.2: empty values are omitted; duplicates are still invalid.
    // No runtime RAR type has a semantic handler. RFC 9396 §7 constraints
    // must not disappear while consuming a code or rotating a refresh token.
    if effective_token_param(params, "authorization_details", issuer_base)?
        .is_some_and(|value| !value.is_empty())
    {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_authorization_details",
            Some("authorization_details are not supported at the token endpoint"),
            issuer_base,
        ));
    }
    let grant_type = effective_token_param(params, "grant_type", issuer_base)?
        .ok_or_else(|| missing_required_token_param_error("grant_type", issuer_base))?;
    // This known restriction must not silently disappear on an unsupported grant.
    // Unknown names remain ignored; empty canonical values are omitted by the helper.
    if effective_token_param(params, "organization_id", issuer_base)?.is_some()
        && grant_type != "urn:ietf:params:oauth:grant-type:token-exchange"
    {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("organization_id is supported only by the application token-exchange extension"),
            issuer_base,
        ));
    }
    Ok(TokenForm {
        grant_type,
        code: effective_token_param(params, "code", issuer_base)?,
        client_id: effective_token_param(params, "client_id", issuer_base)?,
        client_secret: effective_token_param(params, "client_secret", issuer_base)?,
        code_verifier: effective_token_param(params, "code_verifier", issuer_base)?,
        redirect_uri: effective_token_param(params, "redirect_uri", issuer_base)?,
        scope: effective_token_param(params, "scope", issuer_base)?,
        refresh_token: effective_token_param(params, "refresh_token", issuer_base)?,
        assertion: effective_token_param(params, "assertion", issuer_base)?,
        client_assertion_type: effective_token_param(params, "client_assertion_type", issuer_base)?,
        client_assertion: effective_token_param(params, "client_assertion", issuer_base)?,
        device_code: effective_token_param(params, "device_code", issuer_base)?,
    })
}

#[cfg(test)]
mod tests;

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
