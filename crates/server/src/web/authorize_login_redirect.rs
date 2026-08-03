use axum::{
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use url::form_urlencoded;

use crate::util;

use super::authorize_context::AuthorizeRequestContext;
use super::authorize_request::par_authorize_error_response;
use super::AppState;

fn sanitize_authorize_return_to(uri: &Uri) -> String {
    let path = uri.path();
    let Some(query) = uri.query() else {
        return path.to_string();
    };

    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key == "prompt" {
            let filtered = value
                .split_whitespace()
                .filter(|token| *token != "login")
                .collect::<Vec<_>>()
                .join(" ");
            if !filtered.is_empty() {
                serializer.append_pair("prompt", &filtered);
            }
        } else {
            serializer.append_pair(&key, &value);
        }
    }
    let sanitized_query = serializer.finish();
    if sanitized_query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{sanitized_query}")
    }
}

fn append_authorize_return_to_param(return_to: &str, key: &str, value: &str) -> String {
    let (path, query) = return_to.split_once('?').unwrap_or((return_to, ""));
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (existing_key, existing_value) in form_urlencoded::parse(query.as_bytes()) {
        if existing_key != key {
            serializer.append_pair(&existing_key, &existing_value);
        }
    }
    serializer.append_pair(key, value);
    format!("{path}?{}", serializer.finish())
}

fn build_local_login_redirect(return_to: &str, acr: Option<&str>) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("return_to", return_to);
    if let Some(acr) = acr {
        serializer.append_pair("acr", acr);
    }
    format!("/auth/login?{}", serializer.finish())
}

pub(super) async fn authorize_login_redirect_response(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    uri: &Uri,
    selected_acr: Option<&str>,
    issuer_base: &str,
) -> Response {
    let mut return_to = sanitize_authorize_return_to(uri);
    let continuation = match ctx.req.request_uri.as_deref() {
        Some(request_uri) => {
            match state
                .protocol
                .par_store
                .clone()
                .try_authorize_continuation_async(request_uri.to_string())
                .await
            {
                Ok(continuation) => continuation,
                Err(err) => return par_authorize_error_response(issuer_base, &err),
            }
        }
        None => None,
    };
    if let Some(continuation) = continuation {
        return_to = append_authorize_return_to_param(&return_to, "aeg_par_continue", &continuation);
    }
    let login_redirect = build_local_login_redirect(&return_to, selected_acr);
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(&login_redirect) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    util::apply_no_cache_headers(&mut response);
    response
}
