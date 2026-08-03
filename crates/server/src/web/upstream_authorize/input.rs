use super::super::oauth_errors::json_error_with_iss;
use super::super::{parse_acr_values, select_supported_acr, validate_return_to, AppState};
use axum::{http::StatusCode, response::Response};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub(in crate::web) struct UpstreamAuthorizeQuery {
    return_to: Option<String>,
    scope: Option<String>,
    acr_values: Option<String>,
    max_age: Option<i64>,
}

pub(super) struct UpstreamAuthorizeInput {
    pub(super) return_to: Option<String>,
    pub(super) scopes: Vec<String>,
    pub(super) scope: String,
    pub(super) acr: Option<String>,
    pub(super) max_age: Option<i64>,
}

pub(super) fn parse_upstream_authorize_input(
    state: &AppState,
    params: UpstreamAuthorizeQuery,
    issuer_base: &str,
) -> Result<UpstreamAuthorizeInput, Response> {
    let return_to = validate_return_to(params.return_to).map_err(|message| {
        json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&message),
            issuer_base,
        )
    })?;
    if let Some(max_age) = params.max_age {
        if max_age < 0 {
            return Err(json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("max_age must be non-negative"),
                issuer_base,
            ));
        }
    }

    let mut scopes: Vec<String> = params
        .scope
        .unwrap_or_else(|| "openid".to_string())
        .split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect();
    if !scopes.iter().any(|value| value == "openid") {
        scopes.insert(0, "openid".to_string());
    }
    if scopes.is_empty() {
        scopes.push("openid".to_string());
    }

    let requested_acr = parse_acr_values(params.acr_values.as_deref());
    let acr = if requested_acr.is_empty() {
        None
    } else if state.cfg.acr_values_supported.is_empty() {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("acr_values are not supported"),
            issuer_base,
        ));
    } else {
        Some(
            select_supported_acr(&requested_acr, &state.cfg.acr_values_supported).ok_or_else(
                || {
                    json_error_with_iss(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        Some("requested acr_values are not supported"),
                        issuer_base,
                    )
                },
            )?,
        )
    };

    Ok(UpstreamAuthorizeInput {
        return_to,
        scope: scopes.join(" "),
        scopes,
        acr,
        max_age: params.max_age,
    })
}
