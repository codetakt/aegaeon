use axum::response::Response;
use http::{HeaderMap, StatusCode};
use std::sync::Arc;

use super::super::{
    form_field, reject_duplicate_form_fields, render_local_login_form, render_local_result_page,
    try_validate_form_csrf, validate_return_to, LOCAL_AUTH_CSRF_COOKIE_NAME,
};
use crate::device_authz::CsrfTokenStore;
use crate::web::local_auth_support::{
    local_auth_response, local_auth_response_with_csrf_cookie,
    local_csrf_store_unavailable_response, try_local_csrf_token, try_local_csrf_token_async,
};
use crate::web::normalized_acr;

pub(in crate::web) struct LocalLoginSubmission {
    pub(in crate::web) return_to: Option<String>,
    pub(in crate::web) requested_acr: Option<String>,
    pub(in crate::web) identifier: String,
    pub(in crate::web) password: String,
}

fn local_login_form_response(
    csrf_store: &CsrfTokenStore,
    status: StatusCode,
    return_to: Option<&str>,
    acr: Option<&str>,
    message: &str,
) -> Response {
    let csrf_token = match try_local_csrf_token(csrf_store) {
        Ok(token) => token,
        Err(response) => return response,
    };
    local_auth_response_with_csrf_cookie(
        status,
        render_local_login_form(return_to, acr, &csrf_token, Some(message)),
        &csrf_token,
    )
}

pub(in crate::web::local_auth) async fn local_login_form_response_async(
    csrf_store: Arc<CsrfTokenStore>,
    status: StatusCode,
    return_to: Option<&str>,
    acr: Option<&str>,
    message: &str,
) -> Response {
    let csrf_token = match try_local_csrf_token_async(csrf_store).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    local_auth_response_with_csrf_cookie(
        status,
        render_local_login_form(return_to, acr, &csrf_token, Some(message)),
        &csrf_token,
    )
}

pub(in crate::web) fn parse_local_login_submission(
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    csrf_store: &CsrfTokenStore,
) -> Result<LocalLoginSubmission, Response> {
    let Ok(axum::extract::Form(params)) = form else {
        return Err(local_login_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            None,
            None,
            "Invalid form submission.",
        ));
    };

    if reject_duplicate_form_fields(
        &params,
        &["return_to", "acr", "csrf_token", "identifier", "password"],
    )
    .is_err()
    {
        return Err(local_login_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            None,
            None,
            "Invalid form submission.",
        ));
    }

    let field = |name| form_field(&params, name).ok().flatten();
    let return_to = match validate_return_to(field("return_to")) {
        Ok(return_to) => return_to,
        Err(message) => {
            return Err(local_login_form_response(
                csrf_store,
                StatusCode::BAD_REQUEST,
                None,
                None,
                &message,
            ));
        }
    };
    let requested_acr = normalized_acr(field("acr").as_deref());
    match try_validate_form_csrf(headers, &params, LOCAL_AUTH_CSRF_COOKIE_NAME, csrf_store) {
        Ok(true) => {}
        Ok(false) => {
            return Err(local_login_form_response(
                csrf_store,
                StatusCode::BAD_REQUEST,
                return_to.as_deref(),
                requested_acr.as_deref(),
                "The form token is invalid or expired.",
            ));
        }
        Err(err) => return Err(local_csrf_store_unavailable_response(&err)),
    }
    let Some(identifier) = field("identifier")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Err(local_login_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            return_to.as_deref(),
            requested_acr.as_deref(),
            "Email or subject is required.",
        ));
    };
    let Some(password) = field("password").filter(|value| !value.is_empty()) else {
        return Err(local_login_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            return_to.as_deref(),
            requested_acr.as_deref(),
            "Password is required.",
        ));
    };

    Ok(LocalLoginSubmission {
        return_to,
        requested_acr,
        identifier,
        password,
    })
}

pub(in crate::web::local_auth) async fn parse_local_login_submission_async(
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    csrf_store: Arc<CsrfTokenStore>,
) -> Result<LocalLoginSubmission, Response> {
    let headers = headers.clone();
    tokio::task::spawn_blocking(move || parse_local_login_submission(&headers, form, &csrf_store))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "local login admission worker failed");
            local_auth_response(
                StatusCode::SERVICE_UNAVAILABLE,
                render_local_result_page(
                    "Temporarily unavailable",
                    "Local credential authentication is temporarily unavailable. Please try again.",
                    None,
                ),
            )
        })?
}
