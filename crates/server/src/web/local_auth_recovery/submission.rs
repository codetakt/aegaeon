use super::super::local_auth_support::{
    local_auth_response, local_csrf_store_unavailable_response,
};
use super::super::{
    form_field, reject_duplicate_form_fields, render_local_result_page,
    try_validate_form_csrf_async, validate_return_to, LOCAL_AUTH_CSRF_COOKIE_NAME,
};
use super::presentation::local_recovery_form_response;
use crate::device_authz::CsrfTokenStore;
use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::organizations::request_work::async_store::blocking;
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

async fn invalid_form_response(
    csrf_store: &Arc<CsrfTokenStore>,
    purpose: RecoveryTokenPurpose,
) -> Response {
    local_recovery_form_response(
        csrf_store,
        StatusCode::BAD_REQUEST,
        purpose,
        None,
        None,
        "Invalid form submission.",
    )
    .await
}

async fn parse_recovery_form(
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    purpose: RecoveryTokenPurpose,
    csrf_store: &Arc<CsrfTokenStore>,
) -> Result<Vec<(String, String)>, Response> {
    let Ok(axum::extract::Form(params)) = form else {
        return Err(invalid_form_response(csrf_store, purpose).await);
    };

    if reject_duplicate_form_fields(&params, LOCAL_RECOVERY_SINGLETON_FIELDS).is_err() {
        return Err(invalid_form_response(csrf_store, purpose).await);
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

async fn validate_recovery_csrf(
    headers: &HeaderMap,
    params: &[(String, String)],
    purpose: RecoveryTokenPurpose,
    csrf_store: &Arc<CsrfTokenStore>,
    token_for_redisplay: Option<&str>,
    return_to: Option<&str>,
) -> Result<(), Response> {
    match try_validate_form_csrf_async(
        headers,
        params,
        LOCAL_AUTH_CSRF_COOKIE_NAME,
        csrf_store.clone(),
    )
    .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            token_for_redisplay,
            return_to,
            "The form token is invalid or expired.",
        )
        .await),
        Err(err) => Err(local_csrf_store_unavailable_response(&err)),
    }
}

async fn require_recovery_token(
    params: &[(String, String)],
    purpose: RecoveryTokenPurpose,
    csrf_store: &Arc<CsrfTokenStore>,
    return_to: Option<&str>,
) -> Result<String, Response> {
    if let Some(token) = recovery_form_field(params, "token")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Ok(token)
    } else {
        Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            None,
            return_to,
            "One-time token is required.",
        )
        .await)
    }
}

async fn validate_recovery_password(
    params: &[(String, String)],
    purpose: RecoveryTokenPurpose,
    csrf_store: &Arc<CsrfTokenStore>,
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
        )
        .await);
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
        )
        .await);
    };
    if password != password_confirmation {
        return Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            Some(token),
            return_to,
            "Passwords do not match.",
        )
        .await);
    }
    if let Err(message) = local_credentials::validate_password(&password) {
        return Err(local_recovery_form_response(
            csrf_store,
            StatusCode::BAD_REQUEST,
            purpose,
            Some(token),
            return_to,
            message,
        )
        .await);
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

pub(in crate::web) async fn parse_local_recovery_submission(
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    purpose: RecoveryTokenPurpose,
    csrf_store: &Arc<CsrfTokenStore>,
) -> Result<LocalRecoverySubmission, Response> {
    let params = parse_recovery_form(form, purpose, csrf_store).await?;
    let return_to = validate_recovery_return_to(&params)?;
    let token_for_redisplay = recovery_token_for_redisplay(&params);
    validate_recovery_csrf(
        headers,
        &params,
        purpose,
        csrf_store,
        token_for_redisplay.as_deref(),
        return_to.as_deref(),
    )
    .await?;
    let token = require_recovery_token(&params, purpose, csrf_store, return_to.as_deref()).await?;
    let password =
        validate_recovery_password(&params, purpose, csrf_store, &token, return_to.as_deref())
            .await?;
    let password_hash = blocking(move || hash_recovery_password(&password))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "local recovery hash worker failed");
            local_auth_response(
                StatusCode::SERVICE_UNAVAILABLE,
                render_local_result_page("Temporarily unavailable", "Please try again.", None),
            )
        })??;

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
    parse_local_recovery_submission(headers, form, purpose, &csrf_store).await
}
