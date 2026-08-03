use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::device_authz::{CsrfTokenStore, CsrfTokenStoreError};
use crate::util;
use std::sync::Arc;

use super::super::super::form_helpers::append_csrf_cookie;

pub(super) const DEVICE_CSRF_COOKIE_NAME: &str = "aegaeon_device_csrf";

pub(super) fn device_html_response_with_csrf_cookie(
    status: StatusCode,
    html: String,
    csrf_token: &str,
) -> Response {
    let mut response = (status, Html(html)).into_response();
    util::apply_auth_html_security_headers(&mut response);
    append_csrf_cookie(
        &mut response,
        DEVICE_CSRF_COOKIE_NAME,
        "/device",
        csrf_token,
    );
    response
}

pub(super) fn device_csrf_store_unavailable_response(error: &CsrfTokenStoreError) -> Response {
    tracing::error!(error = %error, "device CSRF token store unavailable");
    device_result_page_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "Temporarily Unavailable",
        "Device verification is temporarily unavailable. Please try again.",
    )
}

pub(super) async fn try_device_csrf_token_async(
    csrf_store: Arc<CsrfTokenStore>,
) -> Result<String, Response> {
    csrf_store
        .try_generate_async()
        .await
        .map_err(|err| device_csrf_store_unavailable_response(&err))
}

pub(super) async fn device_user_code_form_response_async(
    csrf_store: Arc<CsrfTokenStore>,
    status: StatusCode,
    user_code: Option<&str>,
    message: Option<&str>,
) -> Response {
    let csrf_token = match try_device_csrf_token_async(csrf_store).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let html = crate::device_authz::render_user_code_form(&csrf_token, user_code, message);
    device_html_response_with_csrf_cookie(status, html, &csrf_token)
}

pub(super) fn device_result_response(status: StatusCode, html: String) -> Response {
    let mut response = (status, Html(html)).into_response();
    util::apply_auth_html_security_headers(&mut response);
    response
}

pub(super) fn device_result_page_response(
    status: StatusCode,
    title: &str,
    message: &str,
) -> Response {
    device_result_response(
        status,
        crate::device_authz::render_result_page(title, message),
    )
}
