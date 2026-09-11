use axum::{
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use url::form_urlencoded;

use crate::util;

use super::authorize_context::AuthorizeRequestContext;
use super::AppState;

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
    _issuer_base: &str,
) -> Response {
    let (return_to, browser_cookie) =
        match super::authorize_reauthentication::create(state, ctx, uri).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    let login_redirect = build_local_login_redirect(&return_to, selected_acr);
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(&login_redirect) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    if let Ok(value) = HeaderValue::from_str(&browser_cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    util::apply_no_cache_headers(&mut response);
    response
}
