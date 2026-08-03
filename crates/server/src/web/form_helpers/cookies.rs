use axum::{
    http::{header, HeaderMap, HeaderValue},
    response::Response,
};

use crate::device_authz::{CsrfTokenStore, CsrfTokenStoreError};
use crate::util;
use std::sync::Arc;

use super::super::{AUTH_SESSION_COOKIE_NAME, CSRF_COOKIE_MAX_AGE_SECS};
use super::fields::form_field;

pub(in crate::web) fn cookie_value(header: &str, name: &str) -> Option<String> {
    for part in header.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=')?;
        if k.trim() == name {
            let value = v.trim();
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

pub(in crate::web) fn build_session_set_cookie(sid: &str, max_age_secs: u64) -> String {
    format!(
        "{AUTH_SESSION_COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age={max_age_secs}"
    )
}

fn build_session_clear_cookie() -> String {
    format!("{AUTH_SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0")
}

fn build_csrf_set_cookie(name: &str, path: &str, token: &str) -> String {
    format!(
        "{name}={token}; Path={path}; HttpOnly; SameSite=Lax; Secure; Max-Age={CSRF_COOKIE_MAX_AGE_SECS}"
    )
}

fn append_set_cookie(response: &mut Response, set_cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(set_cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub(in crate::web) fn append_csrf_cookie(
    response: &mut Response,
    name: &str,
    path: &str,
    token: &str,
) {
    append_set_cookie(response, &build_csrf_set_cookie(name, path, token));
}

pub(in crate::web) fn csrf_cookie_matches(
    headers: &HeaderMap,
    cookie_name: &str,
    submitted_token: &str,
) -> bool {
    single_cookie_header(headers)
        .ok()
        .flatten()
        .and_then(|cookie_header| cookie_value(cookie_header, cookie_name))
        .is_some_and(|cookie_token| {
            util::constant_time_eq(cookie_token.as_bytes(), submitted_token.as_bytes())
        })
}

pub(in crate::web) fn single_cookie_header(
    headers: &HeaderMap,
) -> Result<Option<&str>, util::SingleHeaderError> {
    util::single_header_str(headers, header::COOKIE.as_str())
}

pub(in crate::web) fn auth_session_cookie(
    headers: &HeaderMap,
) -> Result<Option<String>, util::SingleHeaderError> {
    Ok(single_cookie_header(headers)?
        .and_then(|cookie_header| cookie_value(cookie_header, AUTH_SESSION_COOKIE_NAME)))
}

pub(in crate::web) fn try_validate_form_csrf(
    headers: &HeaderMap,
    params: &[(String, String)],
    cookie_name: &str,
    csrf_store: &CsrfTokenStore,
) -> Result<bool, CsrfTokenStoreError> {
    let Some(submitted_token) = form_field(params, "csrf_token")
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };
    if !csrf_cookie_matches(headers, cookie_name, &submitted_token) {
        return Ok(false);
    }
    csrf_store.try_validate(&submitted_token)
}

pub(in crate::web) async fn try_validate_form_csrf_async(
    headers: &HeaderMap,
    params: &[(String, String)],
    cookie_name: &str,
    csrf_store: Arc<CsrfTokenStore>,
) -> Result<bool, CsrfTokenStoreError> {
    let Some(submitted_token) = form_field(params, "csrf_token")
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };
    if !csrf_cookie_matches(headers, cookie_name, &submitted_token) {
        return Ok(false);
    }
    csrf_store.try_validate_async(submitted_token).await
}

pub(in crate::web) fn apply_auth_session_clear_cookie(response: &mut Response) {
    if let Ok(value) = HeaderValue::from_str(&build_session_clear_cookie()) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}
