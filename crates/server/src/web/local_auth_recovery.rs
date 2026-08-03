mod presentation;
mod submission;

use super::local_auth_audit::{
    load_local_auth_audit_environment, local_auth_audit_failure_response, write_local_auth_audit,
    LocalAuthAuditEvent,
};
use super::local_auth_support::{
    local_auth_response, local_auth_response_with_csrf_cookie, local_auth_unavailable_response,
    try_local_csrf_token_async,
};
use super::{
    build_session_set_cookie, clock_error_response, create_auth_session_or_error_response_async,
    enforce_no_credentials_in_uri_with_policy, now_epoch_secs, render_local_password_form,
    render_local_result_page, request_id_from_headers, validate_return_to, AppState,
    AuthSessionTimes, LocalPasswordForm, QueryCredentialPolicy,
};
use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::util;
use axum::extract::{OriginalUri, Query, State};
use axum::response::{IntoResponse, Response};
use http::{header, HeaderMap, HeaderValue, StatusCode};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;

use presentation::{local_recovery_form_response_async, local_recovery_presentation};
#[cfg(test)]
pub(super) use submission::parse_local_recovery_submission;
use submission::parse_local_recovery_submission_async;
use submission::LocalRecoverySubmission;

#[derive(Deserialize, Default)]
pub(super) struct LocalRecoveryQuery {
    token: Option<String>,
    return_to: Option<String>,
}

pub(super) async fn local_activate_get(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<LocalRecoveryQuery>,
) -> Response {
    if let Err(resp) = enforce_no_credentials_in_uri_with_policy(
        &uri,
        state.issuer.as_str(),
        QueryCredentialPolicy::allow(&["token"]),
    ) {
        return resp;
    }
    let return_to = match validate_return_to(query.return_to) {
        Ok(value) => value,
        Err(message) => {
            return local_auth_response(
                StatusCode::BAD_REQUEST,
                render_local_result_page("Invalid request", &message, None),
            );
        }
    };
    let csrf_token =
        match try_local_csrf_token_async(state.device.local_auth_csrf_store.clone()).await {
            Ok(token) => token,
            Err(response) => return response,
        };
    local_auth_response_with_csrf_cookie(
        StatusCode::OK,
        render_local_password_form(LocalPasswordForm {
            title: "Activate account",
            heading: "Activate account",
            action: "/auth/activate",
            submit_label: "Activate account",
            token: query.token.as_deref(),
            return_to: return_to.as_deref(),
            csrf_token: &csrf_token,
            error: None,
        }),
        &csrf_token,
    )
}

pub(super) async fn local_activate_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    handle_local_recovery_post(state, &headers, form, RecoveryTokenPurpose::Activation).await
}

pub(super) async fn local_password_reset_get(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<LocalRecoveryQuery>,
) -> Response {
    if let Err(resp) = enforce_no_credentials_in_uri_with_policy(
        &uri,
        state.issuer.as_str(),
        QueryCredentialPolicy::allow(&["token"]),
    ) {
        return resp;
    }
    let return_to = match validate_return_to(query.return_to) {
        Ok(value) => value,
        Err(message) => {
            return local_auth_response(
                StatusCode::BAD_REQUEST,
                render_local_result_page("Invalid request", &message, None),
            );
        }
    };
    let csrf_token =
        match try_local_csrf_token_async(state.device.local_auth_csrf_store.clone()).await {
            Ok(token) => token,
            Err(response) => return response,
        };
    local_auth_response_with_csrf_cookie(
        StatusCode::OK,
        render_local_password_form(LocalPasswordForm {
            title: "Reset password",
            heading: "Reset password",
            action: "/auth/password/reset",
            submit_label: "Reset password",
            token: query.token.as_deref(),
            return_to: return_to.as_deref(),
            csrf_token: &csrf_token,
            error: None,
        }),
        &csrf_token,
    )
}

pub(super) async fn local_password_reset_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    handle_local_recovery_post(state, &headers, form, RecoveryTokenPurpose::PasswordReset).await
}

async fn local_recovery_success_response(
    state: &AppState,
    purpose: RecoveryTokenPurpose,
    submission: &LocalRecoverySubmission,
    redeemed: local_credentials::RedeemedRecoveryToken,
) -> Response {
    let presentation = local_recovery_presentation(purpose);
    let sid = match create_auth_session_or_error_response_async(
        &state.browser_auth.auth_sessions,
        state.issuer.as_str(),
        redeemed.subject.clone(),
        AuthSessionTimes::local(match now_epoch_secs() {
            Ok(now) => now,
            Err(_) => return clock_error_response(state.issuer.as_str()),
        }),
        state.cfg.local_password_acr.clone(),
        None,
        None,
    )
    .await
    {
        Ok(sid) => sid,
        Err(response) => return response,
    };
    let cookie = build_session_set_cookie(&sid, state.browser_auth.auth_sessions.cookie_ttl_secs());
    if let Some(return_to) = submission.return_to.as_deref() {
        let mut response = StatusCode::SEE_OTHER.into_response();
        if let Ok(value) = HeaderValue::from_str(return_to) {
            response.headers_mut().insert(header::LOCATION, value);
        }
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
        util::apply_no_cache_headers(&mut response);
        response
    } else {
        let mut response = local_auth_response(
            StatusCode::OK,
            render_local_result_page(
                presentation.title,
                "The one-time token has been redeemed successfully.",
                None,
            ),
        );
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
        response
    }
}

async fn local_recovery_failure_response(
    state: &AppState,
    pool: &PgPool,
    purpose: RecoveryTokenPurpose,
    submission: &LocalRecoverySubmission,
    request_id: &str,
) -> Response {
    let environment = match load_local_auth_audit_environment(pool, state.issuer.as_str()).await {
        Ok(Some(environment)) => environment,
        Ok(None) => return local_auth_unavailable_response(),
        Err(response) => return response,
    };
    if write_local_auth_audit(
        pool,
        LocalAuthAuditEvent {
            environment: &environment,
            event_type: local_recovery_presentation(purpose).failure_event_type,
            outcome: "failure",
            severity: "warn",
            actor_type: "anonymous",
            actor_id: None,
            target_type: "environment",
            target_id: Some(&environment.environment_id.to_string()),
            request_id,
            data: json!({
                "purpose": purpose.as_audit_label(),
                "reason": "invalid_or_expired_token"
            }),
        },
    )
    .await
    .is_err()
    {
        return local_auth_audit_failure_response();
    }

    local_recovery_form_response_async(
        state.device.local_auth_csrf_store.clone(),
        StatusCode::BAD_REQUEST,
        purpose,
        Some(&submission.token),
        submission.return_to.as_deref(),
        "The token is invalid, expired, or already used.",
    )
    .await
}

async fn handle_local_recovery_post(
    state: AppState,
    headers: &HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    purpose: RecoveryTokenPurpose,
) -> Response {
    let pool = &state.db_pool;
    let request_id = request_id_from_headers(headers);
    let submission = match parse_local_recovery_submission_async(
        headers,
        form,
        purpose,
        state.device.local_auth_csrf_store.clone(),
    )
    .await
    {
        Ok(submission) => submission,
        Err(response) => return response,
    };

    match local_credentials::redeem_recovery_token(
        pool,
        state.issuer.as_str(),
        &submission.token,
        purpose,
        &submission.password_hash,
        &request_id,
    )
    .await
    {
        Ok(Some(redeemed)) => {
            local_recovery_success_response(&state, purpose, &submission, redeemed).await
        }
        Ok(None) => {
            local_recovery_failure_response(&state, pool, purpose, &submission, &request_id).await
        }
        Err(_) => local_auth_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            render_local_result_page(
                "Server error",
                "The server could not process the token redemption request.",
                None,
            ),
        ),
    }
}
