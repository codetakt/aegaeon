use super::super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::super::request_admission::enforce_no_credentials_in_uri;
use super::super::super::AppState;
use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use std::net::SocketAddr;

use crate::util;

use super::action_admission::{
    enforce_action_rate_limit, require_result_user_code, resolve_action_user, result_form_params,
    result_form_user_code, validate_result_form_csrf,
};
use super::response::{device_result_page_response, device_result_response};

pub(in crate::web) async fn device_approve(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    if !state.cfg.grant_runtime().device_authorization_enabled() {
        return no_cache_json_error_with_iss(
            StatusCode::NOT_FOUND,
            "not_found",
            None,
            state.issuer.as_str(),
        );
    }
    if let Err(resp) = enforce_no_credentials_in_uri(&uri, state.issuer.as_str()) {
        return resp;
    }
    let params = match result_form_params(form) {
        Ok(params) => params,
        Err(response) => return response,
    };
    let user_code = result_form_user_code(&params);
    if let Err(response) = validate_result_form_csrf(&state, &headers, &params).await {
        return response;
    }
    let user_code = match require_result_user_code(user_code.as_deref()) {
        Ok(user_code) => user_code,
        Err(response) => return response,
    };
    if let Err(response) = enforce_action_rate_limit(
        &state,
        remote,
        &headers,
        "device approval rate limiter unavailable",
    )
    .await
    {
        return response;
    }
    let user_id = match resolve_action_user(
        &state,
        &headers,
        "Sign in before approving a device authorization request.",
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    let approved = match state
        .device
        .code_store
        .try_approve_async(user_code.clone(), user_id.clone())
        .await
    {
        Ok(approved) => approved,
        Err(err) => {
            tracing::error!(error = %err, "device approval store unavailable");
            return device_result_page_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Temporarily Unavailable",
                "Device authorization is temporarily unavailable. Please try again.",
            );
        }
    };
    if approved {
        let user_code_hash = aegaeon_crypto::hash::sha256_hex(user_code.as_bytes());
        tracing::info!(
            target: "audit",
            event = "device_authz_approved",
            user_code_hash = %user_code_hash,
            user_id = %user_id,
            "device authorization approved"
        );
        let html = crate::device_authz::render_result_page(
            "Device Authorized",
            "You have authorized the device. You may close this window.",
        );
        let mut response = Html(html).into_response();
        util::apply_no_cache_headers(&mut response);
        response
    } else {
        let html = crate::device_authz::render_result_page(
            "Error",
            "The code is invalid, expired, or has already been used.",
        );
        device_result_response(StatusCode::BAD_REQUEST, html)
    }
}

pub(in crate::web) async fn device_deny(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    if !state.cfg.grant_runtime().device_authorization_enabled() {
        return no_cache_json_error_with_iss(
            StatusCode::NOT_FOUND,
            "not_found",
            None,
            state.issuer.as_str(),
        );
    }
    if let Err(resp) = enforce_no_credentials_in_uri(&uri, state.issuer.as_str()) {
        return resp;
    }
    let params = match result_form_params(form) {
        Ok(params) => params,
        Err(response) => return response,
    };
    let user_code = result_form_user_code(&params);
    if let Err(response) = validate_result_form_csrf(&state, &headers, &params).await {
        return response;
    }
    let user_code = match require_result_user_code(user_code.as_deref()) {
        Ok(user_code) => user_code,
        Err(response) => return response,
    };
    if let Err(response) = enforce_action_rate_limit(
        &state,
        remote,
        &headers,
        "device denial rate limiter unavailable",
    )
    .await
    {
        return response;
    }
    let user_id = match resolve_action_user(
        &state,
        &headers,
        "Sign in before denying a device authorization request.",
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    let denied = match state
        .device
        .code_store
        .try_deny_async(user_code.clone())
        .await
    {
        Ok(denied) => denied,
        Err(err) => {
            tracing::error!(error = %err, "device denial store unavailable");
            return device_result_page_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Temporarily Unavailable",
                "Device authorization is temporarily unavailable. Please try again.",
            );
        }
    };
    if denied {
        let user_code_hash = aegaeon_crypto::hash::sha256_hex(user_code.as_bytes());
        tracing::info!(
            target: "audit",
            event = "device_authz_denied",
            user_code_hash = %user_code_hash,
            user_id = %user_id,
            "device authorization denied"
        );
        let html = crate::device_authz::render_result_page(
            "Authorization Denied",
            "You have denied the device authorization request. You may close this window.",
        );
        let mut response = Html(html).into_response();
        util::apply_no_cache_headers(&mut response);
        response
    } else {
        let html = crate::device_authz::render_result_page(
            "Error",
            "The code is invalid, expired, or has already been used.",
        );
        device_result_response(StatusCode::BAD_REQUEST, html)
    }
}
