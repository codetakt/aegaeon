use super::super::local_auth_support::{
    local_auth_response, local_csrf_store_unavailable_response,
};
use super::super::{
    form_field, reject_duplicate_form_fields, render_local_result_page, try_validate_form_csrf,
    validate_return_to, LOCAL_AUTH_CSRF_COOKIE_NAME,
};
use super::presentation::local_recovery_form_response;
use crate::device_authz::CsrfTokenStore;
use crate::local_credentials::{self, RecoveryTokenPurpose};
use axum::response::Response;
use http::{HeaderMap, StatusCode};
use std::sync::Arc;

pub(in crate::web) struct LocalRecoverySubmission {
    pub(super) return_to: Option<String>,
    pub(super) token: String,
    pub(super) password_hash: String,
}

const LOCAL_RECOVERY_SINGLETON_FIELDS: &[&str] = &[
    "return_to",
    "token",
    "csrf_token",
    "password",
    "password_confirmation",
];

fn invalid_form_response(csrf_store: &CsrfTokenStore, purpose: RecoveryTokenPurpose) -> Response {
    local_recovery_form_response(
        csrf_store,
        StatusCode::BAD_REQUEST,
        purpose,
        None,
        None,
        "Invalid form submission.",
    )
}

fn parse_recovery_form(
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    purpose: RecoveryTokenPurpose,
    csrf_store: &CsrfTokenStore,
) -> Result<Vec<(String, String)>, Response> {
    let Ok(axum::extract::Form(params)) = form else {
        return Err(invalid_form_response(csrf_store, purpose));
    };

    if reject_duplicate_form_fields(&params, LOCAL_RECOVERY_SINGLETON_FIELDS).is_err() {
        return Err(invalid_form_response(csrf_store, purpose));
    }
    Ok(params)
}

fn recovery_form_field(params: &[(String, String)], name: &str) -> Option<String> {
    form_field(params, name).ok().flatten()
}

fn recovery_token_for_redisplay(params: &[(String, String)]) -> Option<String> {
    recovery_form_field(params, "token")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn validate_recovery_return_to(params: &[(String, String)]) -> Result<Option<String>, Response> {
    validate_return_to(recovery_form_field(params, "return_to")).map_err(|message| {
        local_auth_response(
            StatusCode::BAD_REQUEST,
            render_local_result_page("Invalid request", &message, None),
        )
    })
}

fn validate_recovery_csrf(
    headers: &HeaderMap,
    params: &[(String, String)],
    purpose: RecoveryTokenPurpose,
    csrf_store: &CsrfTokenStore,
    token_for_redisplay: Option<&str>,
    return_to: Option<&str>,
) -> Result<(), Response> {
    match try_validate_form_csrf(headers, params, LOCAL_AUTH_CSRF_COOKIE_NAME, csrf_store) {
        Ok(true) => Ok(()),
        Ok(false) => Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            token_for_redisplay,
            return_to,
            "The form token is invalid or expired.",
        )),
        Err(err) => Err(local_csrf_store_unavailable_response(&err)),
    }
}

fn require_recovery_token(
    params: &[(String, String)],
    purpose: RecoveryTokenPurpose,
    csrf_store: &CsrfTokenStore,
    return_to: Option<&str>,
) -> Result<String, Response> {
    recovery_form_field(params, "token")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            local_recovery_form_response(
                csrf_store,
                StatusCode::BAD_REQUEST,
                purpose,
                None,
                return_to,
                "One-time token is required.",
            )
        })
}

fn validate_recovery_password(
    params: &[(String, String)],
    purpose: RecoveryTokenPurpose,
    csrf_store: &CsrfTokenStore,
    token: &str,
    return_to: Option<&str>,
) -> Result<String, Response> {
    let Some(password) = recovery_form_field(params, "password").filter(|value| !value.is_empty())
    else {
        return Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            Some(token),
            return_to,
            "Password is required.",
        ));
    };
    let Some(password_confirmation) =
        recovery_form_field(params, "password_confirmation").filter(|value| !value.is_empty())
    else {
        return Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            Some(token),
            return_to,
            "Password confirmation is required.",
        ));
    };
    if password != password_confirmation {
        return Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            Some(token),
            return_to,
            "Passwords do not match.",
        ));
    }
    if let Err(message) = local_credentials::validate_password(&password) {
        return Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            Some(token),
            return_to,
            message,
        ));
    }
    Ok(password)
}

fn hash_recovery_password(password: &str) -> Result<String, Response> {
    local_credentials::hash_password(password).map_err(|message| {
        local_auth_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            render_local_result_page("Server error", &message, None),
        )
    })
}

pub(in crate::web) fn parse_local_recovery_submission(
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    purpose: RecoveryTokenPurpose,
    csrf_store: &CsrfTokenStore,
) -> Result<LocalRecoverySubmission, Response> {
    let params = parse_recovery_form(form, purpose, csrf_store)?;
    let return_to = validate_recovery_return_to(&params)?;
    let token_for_redisplay = recovery_token_for_redisplay(&params);
    validate_recovery_csrf(
        headers,
        &params,
        purpose,
        csrf_store,
        token_for_redisplay.as_deref(),
        return_to.as_deref(),
    )?;
    let token = require_recovery_token(&params, purpose, csrf_store, return_to.as_deref())?;
    let password =
        validate_recovery_password(&params, purpose, csrf_store, &token, return_to.as_deref())?;
    let password_hash = hash_recovery_password(&password)?;

    Ok(LocalRecoverySubmission {
        return_to,
        token,
        password_hash,
    })
}

pub(in crate::web) async fn parse_local_recovery_submission_async(
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    purpose: RecoveryTokenPurpose,
    csrf_store: Arc<CsrfTokenStore>,
) -> Result<LocalRecoverySubmission, Response> {
    let headers = headers.clone();
    tokio::task::spawn_blocking(move || {
        parse_local_recovery_submission(&headers, form, purpose, &csrf_store)
    })
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "local recovery admission worker failed");
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
