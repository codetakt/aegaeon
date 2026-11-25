use super::super::local_auth_support::{
    local_auth_response, local_csrf_store_unavailable_response,
};
use super::super::{
    form_field, reject_duplicate_form_fields, render_local_result_page,
    try_validate_form_csrf_async, validate_return_to, LOCAL_AUTH_CSRF_COOKIE_NAME,
};
use super::presentation::{local_recovery_form_response, RecoveryContext};
use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::organizations::request_work::async_store::blocking;
use axum::response::Response;
use http::{HeaderMap, StatusCode};

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
    context: &RecoveryContext<'_>,
    purpose: RecoveryTokenPurpose,
) -> Response {
    local_recovery_form_response(
        context,
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
    context: &RecoveryContext<'_>,
) -> Result<Vec<(String, String)>, Response> {
    let Ok(axum::extract::Form(params)) = form else {
        return Err(invalid_form_response(context, purpose).await);
    };

    if reject_duplicate_form_fields(&params, LOCAL_RECOVERY_SINGLETON_FIELDS).is_err() {
        return Err(invalid_form_response(context, purpose).await);
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

fn validate_recovery_return_to(
    context: &RecoveryContext<'_>,
    params: &[(String, String)],
) -> Result<Option<String>, Response> {
    validate_return_to(recovery_form_field(params, "return_to")).map_err(|message| {
        local_auth_response(
            StatusCode::BAD_REQUEST,
            render_local_result_page(context.presentation, "Invalid request", &message, None),
        )
    })
}

async fn validate_recovery_csrf(
    headers: &HeaderMap,
    params: &[(String, String)],
    purpose: RecoveryTokenPurpose,
    context: &RecoveryContext<'_>,
    token_for_redisplay: Option<&str>,
    return_to: Option<&str>,
) -> Result<(), Response> {
    match try_validate_form_csrf_async(
        headers,
        params,
        LOCAL_AUTH_CSRF_COOKIE_NAME,
        context.csrf_store.clone(),
    )
    .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(local_recovery_form_response(
            context,
            StatusCode::BAD_REQUEST,
            purpose,
            token_for_redisplay,
            return_to,
            "The form token is invalid or expired.",
        )
        .await),
        Err(err) => Err(local_csrf_store_unavailable_response(
            context.presentation,
            &err,
        )),
    }
}

async fn require_recovery_token(
    params: &[(String, String)],
    purpose: RecoveryTokenPurpose,
    context: &RecoveryContext<'_>,
    return_to: Option<&str>,
) -> Result<String, Response> {
    if let Some(token) = recovery_form_field(params, "token")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Ok(token)
    } else {
        Err(local_recovery_form_response(
            context,
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
    context: &RecoveryContext<'_>,
    token: &str,
    return_to: Option<&str>,
) -> Result<String, Response> {
    let Some(password) = recovery_form_field(params, "password").filter(|value| !value.is_empty())
    else {
        return Err(local_recovery_form_response(
            context,
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
            context,
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
            context,
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
            context,
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

fn hash_failure_response(context: &RecoveryContext<'_>, message: &str) -> Response {
    local_auth_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        render_local_result_page(context.presentation, "Server error", message, None),
    )
}

pub(in crate::web) async fn parse_local_recovery_submission(
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    purpose: RecoveryTokenPurpose,
    context: &RecoveryContext<'_>,
) -> Result<LocalRecoverySubmission, Response> {
    let params = parse_recovery_form(form, purpose, context).await?;
    let return_to = validate_recovery_return_to(context, &params)?;
    let token_for_redisplay = recovery_token_for_redisplay(&params);
    validate_recovery_csrf(
        headers,
        &params,
        purpose,
        context,
        token_for_redisplay.as_deref(),
        return_to.as_deref(),
    )
    .await?;
    let token = require_recovery_token(&params, purpose, context, return_to.as_deref()).await?;
    let password =
        validate_recovery_password(&params, purpose, context, &token, return_to.as_deref()).await?;
    let password_hash = blocking(move || local_credentials::hash_password(&password))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "local recovery hash worker failed");
            local_auth_response(
                StatusCode::SERVICE_UNAVAILABLE,
                render_local_result_page(
                    context.presentation,
                    "Temporarily unavailable",
                    "Please try again.",
                    None,
                ),
            )
        })?
        .map_err(|message| hash_failure_response(context, &message))?;

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
    context: RecoveryContext<'_>,
) -> Result<LocalRecoverySubmission, Response> {
    parse_local_recovery_submission(headers, form, purpose, &context).await
}
