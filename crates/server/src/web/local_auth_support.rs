use super::{append_csrf_cookie, render_local_result_page, LOCAL_AUTH_CSRF_COOKIE_NAME};
use crate::device_authz::{CsrfTokenStore, CsrfTokenStoreError, VerificationRateLimiter};
use crate::util;
use axum::response::{Html, IntoResponse, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::StatusCode;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;

pub(super) fn local_password_acr_error_response() -> Response {
    local_auth_response(
        StatusCode::BAD_REQUEST,
        render_local_result_page(
            "Unsupported authentication context",
            "The requested authentication context is not available for local password sign-in.",
            None,
        ),
    )
}

pub(super) fn local_auth_response(status: StatusCode, html: String) -> Response {
    let mut response = (status, Html(html)).into_response();
    util::apply_auth_html_security_headers(&mut response);
    response
}

pub(super) fn local_auth_response_with_csrf_cookie(
    status: StatusCode,
    html: String,
    csrf_token: &str,
) -> Response {
    let mut response = local_auth_response(status, html);
    append_csrf_cookie(
        &mut response,
        LOCAL_AUTH_CSRF_COOKIE_NAME,
        "/auth",
        csrf_token,
    );
    response
}

pub(super) fn local_auth_unavailable_response() -> Response {
    local_auth_response(
        StatusCode::NOT_FOUND,
        render_local_result_page(
            "Unavailable",
            "Local credential authentication is not enabled on this server.",
            None,
        ),
    )
}

pub(super) fn local_csrf_store_unavailable_response(error: &CsrfTokenStoreError) -> Response {
    tracing::error!(error = %error, "local auth CSRF token store unavailable");
    local_auth_response(
        StatusCode::SERVICE_UNAVAILABLE,
        render_local_result_page(
            "Temporarily unavailable",
            "Local credential authentication is temporarily unavailable. Please try again.",
            None,
        ),
    )
}

pub(super) fn try_local_csrf_token(csrf_store: &CsrfTokenStore) -> Result<String, Response> {
    csrf_store
        .try_generate()
        .map_err(|err| local_csrf_store_unavailable_response(&err))
}

pub(super) async fn try_local_csrf_token_async(
    csrf_store: Arc<CsrfTokenStore>,
) -> Result<String, Response> {
    csrf_store
        .try_generate_async()
        .await
        .map_err(|err| local_csrf_store_unavailable_response(&err))
}

fn encoded_login_principal(identifier: &str) -> String {
    let normalized = identifier.trim().to_ascii_lowercase();
    let digest = aegaeon_crypto::hash::sha256_digest(normalized.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
pub(super) fn login_rate_limit_keys(
    prefix: &str,
    remote: SocketAddr,
    identifier: &str,
) -> [String; 3] {
    login_rate_limit_keys_for_subject(prefix, &remote.ip().to_string(), identifier)
}

pub(super) fn login_rate_limit_keys_for_subject(
    prefix: &str,
    subject: &str,
    identifier: &str,
) -> [String; 3] {
    let principal = encoded_login_principal(identifier);
    [
        format!("{prefix}:ip:{subject}"),
        format!("{prefix}:principal:{principal}"),
        format!("{prefix}:pair:{subject}:{principal}"),
    ]
}

#[cfg(test)]
pub(super) fn login_rate_limit_allows(
    limiter: &VerificationRateLimiter,
    keys: &[String],
) -> Result<bool, String> {
    limiter.try_check_all(keys.iter().map(String::as_str))
}

pub(super) async fn login_rate_limit_allows_async(
    limiter: Arc<VerificationRateLimiter>,
    keys: Vec<String>,
) -> Result<bool, String> {
    limiter.try_check_all_async(keys).await
}
