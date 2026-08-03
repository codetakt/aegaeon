use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Response};
use http::{header, HeaderMap, HeaderValue, StatusCode};
use sqlx::PgPool;
use std::net::SocketAddr;

use super::super::{
    auth_session_cookie, build_session_set_cookie, clock_error_response,
    create_auth_session_or_error_response_async, local_password_session_acr, now_epoch_secs,
    render_local_result_page, request_id_from_headers, transport_rejection, AppState,
    AuthSessionTimes,
};
use super::audit::{local_login_failure_audit_data, local_login_success_audit_data};
use super::submission::{
    local_login_form_response_async, parse_local_login_submission_async, LocalLoginSubmission,
};
use crate::local_credentials;
use crate::util;
use crate::web::authorize_endpoint::{authorize_requested_max_age, stepup_request_id};
use crate::web::local_auth_audit::{
    load_local_auth_audit_environment, local_auth_audit_failure_response, write_local_auth_audit,
    LocalAuthAuditEvent,
};
use crate::web::local_auth_support::{
    local_auth_response, local_auth_unavailable_response, local_password_acr_error_response,
    login_rate_limit_allows_async, login_rate_limit_keys_for_subject,
};

async fn local_login_success_response(
    state: &AppState,
    pool: &PgPool,
    headers: &HeaderMap,
    submission: &LocalLoginSubmission,
    user: local_credentials::AuthenticatedLocalUser,
    request_id: &str,
) -> Response {
    let session_acr = match local_password_session_acr(
        state.cfg.local_password_acr.as_deref(),
        submission.requested_acr.as_deref(),
    ) {
        Ok(acr) => acr,
        Err(_) => return local_password_acr_error_response(),
    };
    let end_user_id = user.end_user_id.to_string();
    if write_local_auth_audit(
        pool,
        LocalAuthAuditEvent {
            environment: &user.environment,
            event_type: "auth.local.login.authorized.v1",
            outcome: "authorized",
            severity: "info",
            actor_type: "end_user",
            actor_id: Some(&user.subject),
            target_type: "end_user",
            target_id: Some(end_user_id.as_str()),
            request_id,
            data: local_login_success_audit_data(&submission.identifier),
        },
    )
    .await
    .is_err()
    {
        return local_auth_audit_failure_response();
    }
    let now = match now_epoch_secs() {
        Ok(now) => now,
        Err(_) => return clock_error_response(state.issuer.as_str()),
    };
    let sid = match create_auth_session_or_error_response_async(
        &state.browser_auth.auth_sessions,
        state.issuer.as_str(),
        user.subject.clone(),
        AuthSessionTimes::local(now),
        session_acr,
        None,
        None,
    )
    .await
    {
        Ok(sid) => sid,
        Err(response) => return response,
    };
    complete_stepup_for_local_login(
        state.protocol.stepup_store.as_ref(),
        headers,
        submission,
        &sid,
        now,
    );
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
                "Signed in",
                "Your local sign-in succeeded. You may close this window.",
                None,
            ),
        );
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
        response
    }
}

fn authorize_request_from_return_to(
    return_to: &str,
) -> Option<crate::authcode::types::AuthorizationRequest> {
    let (path, query) = return_to.split_once('?').unwrap_or((return_to, ""));
    if path != "/authorize" || query.is_empty() {
        return None;
    }
    serde_urlencoded::from_str(query).ok()
}

fn complete_stepup_for_local_login(
    store: &crate::stepup::StepUpStore,
    headers: &HeaderMap,
    submission: &LocalLoginSubmission,
    new_session_id: &str,
    now: u64,
) {
    let Some(return_to) = submission.return_to.as_deref() else {
        return;
    };
    let Some(req) = authorize_request_from_return_to(return_to) else {
        return;
    };
    let old_session_id = match auth_session_cookie(headers) {
        Ok(Some(session_id)) => session_id,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!(error = ?err, "step-up completion ignored invalid auth-session cookie");
            return;
        }
    };
    let request_id = stepup_request_id(
        &req,
        submission.requested_acr.as_deref(),
        authorize_requested_max_age(&req),
    );
    let completed =
        match store.try_complete_for_request(&req.client_id, &old_session_id, &request_id, now) {
            Ok(Some(challenge)) => challenge,
            Ok(None) => return,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    client_id = %req.client_id,
                    session_id = %old_session_id,
                    request_id = %request_id,
                    "step-up challenge completion failed after local login"
                );
                return;
            }
        };

    let successor =
        match store.try_issue_challenge(&req.client_id, new_session_id, &request_id, now) {
            Ok(Some(challenge)) => challenge,
            Ok(None) => {
                tracing::warn!(
                    client_id = %req.client_id,
                    session_id = %new_session_id,
                    request_id = %request_id,
                    "step-up successor challenge expiry overflowed"
                );
                return;
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    client_id = %req.client_id,
                    session_id = %new_session_id,
                    request_id = %request_id,
                    "step-up successor challenge issue failed"
                );
                return;
            }
        };
    match store.try_complete_for_request(&req.client_id, new_session_id, &request_id, now) {
        Ok(Some(_)) => {
            crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
                metrics.record_stepup_event("challenge_completed");
            });
            tracing::info!(
                client_id = %req.client_id,
                old_session_id = %old_session_id,
                new_session_id = %new_session_id,
                challenge_id = %completed.id,
                successor_challenge_id = %successor.id,
                event = "stepup_challenge_completed",
                request_id = %request_id,
                "step-up challenge completed and transferred to the new auth session"
            );
        }
        Ok(None) => tracing::warn!(
            client_id = %req.client_id,
            session_id = %new_session_id,
            request_id = %request_id,
            "step-up successor challenge was not available for completion"
        ),
        Err(err) => tracing::warn!(
            error = %err,
            client_id = %req.client_id,
            session_id = %new_session_id,
            request_id = %request_id,
            "step-up successor challenge completion failed"
        ),
    }
}

async fn local_login_failure_response(
    state: &AppState,
    pool: &PgPool,
    submission: &LocalLoginSubmission,
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
            event_type: "auth.local.login.failed.v1",
            outcome: "failure",
            severity: "warn",
            actor_type: "anonymous",
            actor_id: None,
            target_type: "environment",
            target_id: Some(&environment.environment_id.to_string()),
            request_id,
            data: local_login_failure_audit_data(&submission.identifier),
        },
    )
    .await
    .is_err()
    {
        return local_auth_audit_failure_response();
    }

    local_login_form_response_async(
        state.device.local_auth_csrf_store.clone(),
        StatusCode::UNAUTHORIZED,
        submission.return_to.as_deref(),
        submission.requested_acr.as_deref(),
        "Sign-in failed.",
    )
    .await
}

pub(in crate::web) async fn local_login_post(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    let pool = &state.db_pool;
    let request_id = request_id_from_headers(&headers);
    let submission = match parse_local_login_submission_async(
        &headers,
        form,
        state.device.local_auth_csrf_store.clone(),
    )
    .await
    {
        Ok(submission) => submission,
        Err(response) => return response,
    };

    let rate_limit_subject = match state.transport.rate_limit_subject(Some(remote), &headers) {
        Ok(subject) => subject,
        Err(kind) => return transport_rejection(&state, kind),
    };
    let rate_limit_keys = login_rate_limit_keys_for_subject(
        "local-login",
        &rate_limit_subject,
        &submission.identifier,
    );
    match login_rate_limit_allows_async(
        state.device.local_login_rate_limiter.clone(),
        rate_limit_keys.to_vec(),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return local_login_form_response_async(
                state.device.local_auth_csrf_store.clone(),
                StatusCode::TOO_MANY_REQUESTS,
                submission.return_to.as_deref(),
                submission.requested_acr.as_deref(),
                "Too many sign-in attempts. Please wait and try again.",
            )
            .await;
        }
        Err(err) => {
            tracing::error!(error = %err, "local login rate limiter unavailable");
            return local_login_form_response_async(
                state.device.local_auth_csrf_store.clone(),
                StatusCode::SERVICE_UNAVAILABLE,
                submission.return_to.as_deref(),
                submission.requested_acr.as_deref(),
                "Sign-in is temporarily unavailable. Please try again.",
            )
            .await;
        }
    }

    match local_credentials::authenticate_local_user(
        pool,
        state.issuer.as_str(),
        &submission.identifier,
        &submission.password,
    )
    .await
    {
        Ok(Some(user)) => {
            local_login_success_response(&state, pool, &headers, &submission, user, &request_id)
                .await
        }
        Ok(None) => local_login_failure_response(&state, pool, &submission, &request_id).await,
        Err(_) => local_auth_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            render_local_result_page(
                "Server error",
                "The server could not process the login request.",
                None,
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{header, HeaderValue};
    use std::{sync::Arc, time::Duration};

    fn return_to() -> &'static str {
        "/authorize?response_type=code&client_id=stepup-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid&state=state&nonce=nonce&acr_values=urn%3Amfa&max_age=0"
    }

    fn submission(return_to: Option<&str>) -> LocalLoginSubmission {
        LocalLoginSubmission {
            return_to: return_to.map(ToString::to_string),
            requested_acr: Some("urn:mfa".to_string()),
            identifier: "user@example.com".to_string(),
            password: "password".to_string(),
        }
    }

    fn request_and_id() -> (crate::authcode::types::AuthorizationRequest, String) {
        let req = authorize_request_from_return_to(return_to())
            .expect("authorize return_to should deserialize");
        let request_id =
            stepup_request_id(&req, Some("urn:mfa"), authorize_requested_max_age(&req));
        (req, request_id)
    }

    fn old_session_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("aegaeon_auth_session=old-session"),
        );
        headers
    }

    fn install_test_metrics() {
        if crate::metrics_integration::MetricsIntegration::with_global(|_| ()).is_some() {
            return;
        }
        let registry = prometheus::Registry::new();
        let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&registry)
            .expect("test metrics should initialize");
        let integration = Arc::new(crate::metrics_integration::MetricsIntegration::new(
            Arc::new(metrics),
        ));
        crate::metrics_integration::MetricsIntegration::register_global(&integration);
    }

    fn completed_metric() -> f64 {
        crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
            metrics
                .metrics
                .stepup_events
                .with_label_values(&["challenge_completed"])
                .get()
        })
        .unwrap_or(0.0)
    }

    #[test]
    fn local_login_transfers_completed_stepup_to_new_session() {
        install_test_metrics();
        let store = crate::stepup::StepUpStore::new_process_local_with_ttl_for_tests(
            Duration::from_secs(60),
        );
        let (req, request_id) = request_and_id();
        let challenge = store
            .try_issue_challenge(&req.client_id, "old-session", &request_id, 100)
            .expect("challenge issue should succeed")
            .expect("challenge should be issued");
        assert_eq!(challenge.session_id, "old-session");
        let metric_before = completed_metric();

        complete_stepup_for_local_login(
            &store,
            &old_session_headers(),
            &submission(Some(return_to())),
            "new-session",
            101,
        );

        assert!(store
            .try_consume_completed(&req.client_id, "old-session", &request_id, 101)
            .expect("old challenge should be completed"));
        assert!(store
            .try_consume_completed(&req.client_id, "new-session", &request_id, 101)
            .expect("successor challenge should be completed"));
        assert!(!store
            .try_consume_completed(&req.client_id, "new-session", &request_id, 101)
            .expect("successor replay check should succeed"));
        assert!(completed_metric() >= metric_before + 1.0);
    }

    #[test]
    fn local_login_without_challenge_does_not_create_successor() {
        let store = crate::stepup::StepUpStore::new_process_local_with_ttl_for_tests(
            Duration::from_secs(60),
        );
        let (req, request_id) = request_and_id();

        complete_stepup_for_local_login(
            &store,
            &old_session_headers(),
            &submission(Some(return_to())),
            "new-session",
            101,
        );

        assert!(!store
            .try_consume_completed(&req.client_id, "new-session", &request_id, 101)
            .expect("missing challenge should remain fail-closed"));
    }

    #[test]
    fn local_login_ignores_non_authorize_return_to_for_stepup() {
        let store = crate::stepup::StepUpStore::new_process_local_with_ttl_for_tests(
            Duration::from_secs(60),
        );
        complete_stepup_for_local_login(
            &store,
            &old_session_headers(),
            &submission(Some("/auth/login?client_id=stepup-client")),
            "new-session",
            101,
        );
    }
}
