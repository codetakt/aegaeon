use axum::{
    extract,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use std::net::SocketAddr;

use super::super::super::form_helpers::{
    form_field, reject_duplicate_form_fields, try_validate_form_csrf_async,
};
use super::super::super::{resolve_session_user, transport_rejection, AppState};
use super::response::{
    device_csrf_store_unavailable_response, device_result_page_response, device_result_response,
    DEVICE_CSRF_COOKIE_NAME,
};
use crate::util;

pub(super) fn result_form_params(
    form: Result<extract::Form<Vec<(String, String)>>, extract::rejection::FormRejection>,
) -> Result<Vec<(String, String)>, Response> {
    let Ok(extract::Form(params)) = form else {
        return Err(invalid_form_response());
    };
    if reject_duplicate_form_fields(&params, &["csrf_token", "user_code"]).is_err() {
        return Err(invalid_form_response());
    }
    Ok(params)
}

pub(super) fn result_form_user_code(params: &[(String, String)]) -> Option<String> {
    form_field(params, "user_code").ok().flatten()
}

pub(super) async fn validate_result_form_csrf(
    state: &AppState,
    headers: &HeaderMap,
    params: &[(String, String)],
) -> Result<(), Response> {
    match try_validate_form_csrf_async(
        headers,
        params,
        DEVICE_CSRF_COOKIE_NAME,
        state.device.csrf_store.clone(),
    )
    .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(device_result_page_response(
            StatusCode::FORBIDDEN,
            "Session Expired",
            "Your session has expired. Please start over.",
        )),
        Err(err) => Err(device_csrf_store_unavailable_response(&err)),
    }
}

pub(super) fn require_result_user_code(user_code: Option<&str>) -> Result<String, Response> {
    user_code
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            device_result_page_response(StatusCode::BAD_REQUEST, "Error", "Missing user code.")
        })
}

pub(super) async fn enforce_action_rate_limit(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    unavailable_log: &'static str,
) -> Result<(), Response> {
    let subject = state
        .transport
        .rate_limit_subject(Some(remote), headers)
        .map_err(|kind| transport_rejection(state, kind))?;
    match state
        .device
        .rate_limiter
        .clone()
        .try_check_async(subject)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(device_result_page_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too Many Attempts",
            "Too many attempts. Please wait and try again.",
        )),
        Err(err) => {
            tracing::error!(error = %err, "{unavailable_log}");
            Err(device_result_page_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Temporarily Unavailable",
                "Device authorization is temporarily unavailable. Please try again.",
            ))
        }
    }
}

pub(super) async fn resolve_action_user(
    state: &AppState,
    headers: &HeaderMap,
    auth_required_message: &'static str,
) -> Result<String, Response> {
    match resolve_session_user(state, headers, state.issuer.as_str()).await {
        Ok(Some(user_id)) => Ok(user_id),
        Ok(None) => {
            let html = crate::device_authz::render_result_page(
                "Authentication Required",
                auth_required_message,
            );
            let mut response = (StatusCode::UNAUTHORIZED, Html(html)).into_response();
            util::apply_no_cache_headers(&mut response);
            Err(response)
        }
        Err(response) => Err(response),
    }
}

fn invalid_form_response() -> Response {
    device_result_response(
        StatusCode::BAD_REQUEST,
        crate::device_authz::render_result_page("Error", "Invalid form submission."),
    )
}
