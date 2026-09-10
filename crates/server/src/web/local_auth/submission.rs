use axum::response::Response;
use http::{HeaderMap, StatusCode};

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
    pub(in crate::web) csrf_token: String,
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
    state: &super::super::AppState,
    headers: &HeaderMap,
    status: StatusCode,
    return_to: Option<&str>,
    acr: Option<&str>,
    message: &str,
) -> Response {
    let csrf_token =
        match try_local_csrf_token_async(state.device.local_auth_csrf_store.clone()).await {
            Ok(token) => token,
            Err(response) => return response,
        };
    if let Err(response) =
        super::super::authorize_reauthentication::bind_form(state, headers, return_to, &csrf_token)
            .await
    {
        return response;
    }
    local_auth_response_with_csrf_cookie(
        status,
        render_local_login_form(return_to, acr, &csrf_token, Some(message)),
        &csrf_token,
    )
}

#[cfg(test)]
pub(in crate::web) fn parse_local_login_submission(
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    csrf_store: &CsrfTokenStore,
) -> Result<LocalLoginSubmission, Response> {
    parse_with_csrf_status(headers, form, csrf_store, &mut false)
}

fn parse_with_csrf_status(
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    csrf_store: &CsrfTokenStore,
    csrf_admitted: &mut bool,
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
        Ok(true) => *csrf_admitted = true,
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
        csrf_token: field("csrf_token")
            .map(|value| value.trim().to_string())
            .ok_or_else(|| {
                local_login_form_response(
                    csrf_store,
                    StatusCode::BAD_REQUEST,
                    None,
                    None,
                    "Restart sign-in.",
                )
            })?,
    })
}

pub(in crate::web::local_auth) async fn parse_local_login_submission_async(
    state: &super::super::AppState,
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Result<LocalLoginSubmission, Response> {
    // An admission error can consume the old CSRF token. Any retry form for
    // this authorization must issue AND bind its replacement asynchronously.
    let retry = form.as_ref().ok().and_then(|form| {
        let returns = form
            .0
            .iter()
            .filter(|(key, _)| key == "return_to")
            .collect::<Vec<_>>();
        if returns.len() != 1 {
            return None;
        }
        let return_to = validate_return_to(Some(returns[0].1.clone()))
            .ok()
            .flatten()?;
        let acr = normalized_acr(form_field(&form.0, "acr").ok().flatten().as_deref());
        Some((return_to, acr))
    });
    let owned_headers = headers.clone();
    let csrf_store = state.device.local_auth_csrf_store.clone();
    let (result, csrf_admitted) = tokio::task::spawn_blocking(move || {
        let mut csrf_admitted = false;
        let result = parse_with_csrf_status(&owned_headers, form, &csrf_store, &mut csrf_admitted);
        (result, csrf_admitted)
    })
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
    })?;
    // A losing concurrent POST must not replace the winning request's CSRF
    // binding while its credential check is running. Invalid-CSRF requests
    // receive no retry form or Set-Cookie; a fresh GET can explicitly restart.
    if !csrf_admitted {
        return result.map_err(|response| {
            local_auth_response(
                response.status(),
                render_local_result_page(
                    "Invalid sign-in request",
                    "Restart sign-in to obtain a new form.",
                    None,
                ),
            )
        });
    }
    match (result, retry) {
        (Err(response), Some((return_to, acr))) => Err(local_login_form_response_async(
            state,
            headers,
            response.status(),
            Some(&return_to),
            acr.as_deref(),
            "Invalid sign-in submission. Please check your input and try again.",
        )
        .await),
        (result, _) => result,
    }
}
