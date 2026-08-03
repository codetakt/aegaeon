use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::authcode::types::AuthorizationRequest as AuthzReq;
use crate::upstream::UpstreamClaimReleasePolicy;

use super::super::auth_session::AuthSession;
use super::super::authorize_context::AuthorizeRequestContext;
use super::super::form_helpers::auth_session_cookie;
use super::super::oauth_errors::{
    json_error_with_iss, no_cache_header_error, no_cache_json_error_with_iss,
};
use super::super::{
    auth_session_store_lookup_error_response, authorize_error_response, clock_error_response,
    now_epoch_secs, parse_acr_values, select_supported_acr, AppState, AuthorizeErrorContext,
};

pub(super) struct AuthorizeDecision {
    pub(super) now: u64,
    pub(super) cookie_session_id: Option<String>,
    pub(super) current_session: Option<AuthSession>,
    pub(super) selected_acr: Option<String>,
    pub(super) session_acr: Option<String>,
    pub(super) stepup_required: bool,
    pub(super) needs_login: bool,
}

pub(super) struct AuthorizeSessionState {
    pub(super) session_id: Option<String>,
    pub(super) set_cookie: Option<String>,
    pub(super) auth_time_epoch_secs: i64,
    pub(super) user_id: String,
    pub(super) session_acr: Option<String>,
    pub(super) claim_release_policy: Option<UpstreamClaimReleasePolicy>,
}

pub(in crate::web) fn authorize_requested_max_age(req: &AuthzReq) -> Option<u64> {
    req.request_object_claims
        .as_ref()
        .and_then(|claims| claims.max_age)
        .or(req.max_age)
}

fn authorize_error_context<'a>(
    state: &'a AppState,
    ctx: &'a AuthorizeRequestContext,
    issuer_base: &'a str,
) -> AuthorizeErrorContext<'a> {
    AuthorizeErrorContext::with_state_for_echo(
        state.cfg.as_ref(),
        state.clients.as_ref(),
        &ctx.req,
        ctx.response_mode,
        issuer_base,
        ctx.state_for_echo.as_deref(),
    )
}

fn authorize_selected_acr(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    let acr_values = ctx
        .req
        .request_object_claims
        .as_ref()
        .and_then(|claims| claims.acr_values.as_deref())
        .or(ctx.req.acr_values.as_deref());
    let requested = parse_acr_values(acr_values);
    if requested.is_empty() {
        return Ok(None);
    }
    select_supported_acr(&requested, state.cfg.acr_values_supported.as_slice())
        .ok_or_else(|| {
            authorize_error_response(
                authorize_error_context(state, ctx, issuer_base),
                "invalid_request",
                Some("acr_values contains unsupported values"),
            )
        })
        .map(Some)
}

fn stepup_store_cleanup_error_response(issuer_base: &str, error: &str) -> Response {
    tracing::error!(error, "step-up challenge store cleanup failed");
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("step-up challenge store unavailable"),
        issuer_base,
    )
}

fn stepup_store_operation_error_response(
    issuer_base: &str,
    operation: &str,
    error: &str,
) -> Response {
    tracing::error!(error, operation, "step-up challenge store operation failed");
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("step-up challenge store unavailable"),
        issuer_base,
    )
}

pub(super) async fn authorize_decide_session(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &AuthorizeRequestContext,
    issuer_base: &str,
) -> Result<AuthorizeDecision, Response> {
    state
        .protocol
        .stepup_store
        .try_cleanup_expired()
        .map_err(|err| stepup_store_cleanup_error_response(issuer_base, &err))?;
    let now = now_epoch_secs().map_err(|_| clock_error_response(issuer_base))?;
    let prompt_has_none = ctx.prompt.split_whitespace().any(|value| value == "none");
    let prompt_has_login = ctx.prompt.split_whitespace().any(|value| value == "login");
    let cookie_session_id = auth_session_cookie(headers)
        .map_err(|err| no_cache_header_error(issuer_base, "Cookie", err))?
        .filter(|sid| !sid.is_empty());
    let current_session = match cookie_session_id.as_deref() {
        Some(sid) => state
            .browser_auth
            .auth_sessions
            .try_get_async(sid.to_string())
            .await
            .map_err(|err| auth_session_store_lookup_error_response(issuer_base, &err))?,
        None => None,
    };
    let selected_acr = authorize_selected_acr(state, ctx, issuer_base)?;
    let max_age = authorize_requested_max_age(&ctx.req);
    let session_acr = current_session
        .as_ref()
        .and_then(|session| session.acr.clone());
    let acr_mismatch = match (selected_acr.as_deref(), session_acr.as_deref()) {
        (Some(requested), Some(existing)) => requested != existing,
        (Some(_), None) => true,
        _ => false,
    };
    let max_age_exceeded = match (max_age, current_session.as_ref()) {
        (Some(max_age_secs), Some(session)) => {
            now.saturating_sub(session.auth_time_epoch_secs) >= max_age_secs
        }
        (Some(_), None) => true,
        _ => false,
    };
    let stepup_required = acr_mismatch || max_age_exceeded;
    if stepup_required {
        let reason = match (acr_mismatch, max_age_exceeded) {
            (true, true) => "required_acr_and_max_age",
            (true, false) => "required_acr_mismatch",
            (false, true) => "required_max_age",
            (false, false) => "required_unknown",
        };
        crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
            metrics.record_stepup_event(reason);
        });
        tracing::info!(
            client_id = %ctx.client_id_for_error,
            event = "stepup_required",
            reason = reason,
            prompt = %ctx.prompt,
            "step-up authentication required"
        );
    }
    let needs_login = current_session.is_none() || prompt_has_login || stepup_required;
    if prompt_has_none && needs_login {
        let description = if stepup_required {
            "prompt=none but step-up authentication is required"
        } else {
            "prompt=none but user is not logged in"
        };
        crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
            metrics.record_stepup_event("prompt_none_login_required");
        });
        tracing::info!(
            client_id = %ctx.client_id_for_error,
            event = "stepup_prompt_none_rejected",
            stepup_required = stepup_required,
            "prompt=none rejected"
        );
        return Err(authorize_error_response(
            authorize_error_context(state, ctx, issuer_base),
            "login_required",
            Some(description),
        ));
    }
    Ok(AuthorizeDecision {
        now,
        cookie_session_id,
        current_session,
        selected_acr,
        session_acr,
        stepup_required,
        needs_login,
    })
}

pub(super) async fn resolve_authorize_session_state(
    decision: &AuthorizeDecision,
    issuer_base: &str,
) -> Result<AuthorizeSessionState, Response> {
    let Some(session) = decision.current_session.as_ref() else {
        return Err(json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("session state inconsistent"),
            issuer_base,
        ));
    };
    Ok(AuthorizeSessionState {
        session_id: decision.cookie_session_id.clone(),
        set_cookie: None,
        auth_time_epoch_secs: session.auth_time_epoch_secs.cast_signed(),
        user_id: session.user_id.clone(),
        session_acr: decision.session_acr.clone(),
        claim_release_policy: session.claim_release_policy.clone(),
    })
}

fn authorize_session_satisfies_stepup(
    ctx: &AuthorizeRequestContext,
    decision: &AuthorizeDecision,
    session: &AuthorizeSessionState,
) -> bool {
    let acr_satisfied = decision
        .selected_acr
        .as_deref()
        .is_none_or(|requested| session.session_acr.as_deref() == Some(requested));
    let max_age_satisfied = authorize_requested_max_age(&ctx.req).is_none_or(|max_age| {
        u64::try_from(session.auth_time_epoch_secs)
            .ok()
            .is_some_and(|auth_time| decision.now.saturating_sub(auth_time) <= max_age)
    });
    acr_satisfied && max_age_satisfied
}

pub(in crate::web) fn stepup_request_id(
    req: &AuthzReq,
    acr: Option<&str>,
    max_age: Option<u64>,
) -> String {
    fn hash_component(hasher: &mut aegaeon_crypto::hash::Sha256Hasher, label: &str, value: &str) {
        hasher.update(label.as_bytes());
        hasher.update(&[0]);
        hasher.update(value.as_bytes());
        hasher.update(&[0]);
    }

    let mut hasher = aegaeon_crypto::hash::Sha256Hasher::new();
    hash_component(&mut hasher, "client_id", &req.client_id);
    hash_component(&mut hasher, "response_type", &req.response_type);

    if let Some(value) = req.redirect_uri.as_deref() {
        hash_component(&mut hasher, "redirect_uri", value);
    }
    if let Some(value) = req.scope.as_deref() {
        hash_component(&mut hasher, "scope", value);
    }
    if let Some(value) = req.state.as_deref() {
        hash_component(&mut hasher, "state", value);
    }
    if let Some(value) = req.nonce.as_deref() {
        hash_component(&mut hasher, "nonce", value);
    }
    if let Some(value) = req.resource.as_deref() {
        hash_component(&mut hasher, "resource", value);
    }
    if let Some(value) = req.request_uri.as_deref() {
        hash_component(&mut hasher, "request_uri", value);
    }
    if let Some(value) = req.request_object.as_deref() {
        hash_component(&mut hasher, "request_object", value);
    }
    if let Some(value) = req.authorization_details.as_ref() {
        if let Ok(serialized) = serde_json::to_string(value) {
            hash_component(&mut hasher, "authorization_details", &serialized);
        }
    }
    if let Some(value) = acr {
        hash_component(&mut hasher, "acr", value);
    }
    if let Some(value) = max_age {
        hash_component(&mut hasher, "max_age", &value.to_string());
    }

    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[derive(Debug)]
enum StepUpGateStoreOutcome {
    Consumed,
    Issued(Option<crate::stepup::StepUpChallenge>),
}

fn try_advance_stepup_challenge(
    store: &crate::stepup::StepUpStore,
    client_id: &str,
    session_id: &str,
    request_id: &str,
    now: u64,
) -> Result<StepUpGateStoreOutcome, String> {
    if store.try_consume_completed(client_id, session_id, request_id, now)? {
        crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
            metrics.record_stepup_event("challenge_consumed");
        });
        return Ok(StepUpGateStoreOutcome::Consumed);
    }
    let challenge = store.try_issue_challenge(client_id, session_id, request_id, now)?;
    if challenge.is_some() {
        crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
            metrics.record_stepup_event("challenge_issued");
        });
    }
    Ok(StepUpGateStoreOutcome::Issued(challenge))
}

pub(super) fn authorize_stepup_gate(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    decision: &AuthorizeDecision,
    session: &AuthorizeSessionState,
    issuer_base: &str,
) -> Result<bool, Response> {
    if !decision.stepup_required {
        return Ok(true);
    }
    if decision.needs_login && authorize_session_satisfies_stepup(ctx, decision, session) {
        crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
            metrics.record_stepup_event("fresh_login_satisfied");
        });
        tracing::info!(
            client_id = %ctx.client_id_for_error,
            event = "stepup_fresh_login_satisfied",
            "step-up requirement satisfied by a fresh local authentication"
        );
        return Ok(true);
    }
    let Some(session_id) = session.session_id.as_deref() else {
        crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
            metrics.record_stepup_event("challenge_missing_session");
        });
        return Err(authorize_error_response(
            authorize_error_context(state, ctx, issuer_base),
            "server_error",
            Some("step-up session is missing"),
        ));
    };
    let request_id = stepup_request_id(
        &ctx.req,
        decision.selected_acr.as_deref(),
        authorize_requested_max_age(&ctx.req),
    );
    match try_advance_stepup_challenge(
        state.protocol.stepup_store.as_ref(),
        &ctx.req.client_id,
        session_id,
        &request_id,
        decision.now,
    ) {
        Ok(StepUpGateStoreOutcome::Consumed) => {
            tracing::info!(
                client_id = %ctx.client_id_for_error,
                session_id = %session_id,
                event = "stepup_challenge_consumed",
                request_id = %request_id,
                "completed step-up challenge consumed"
            );
            Ok(true)
        }
        Ok(StepUpGateStoreOutcome::Issued(challenge)) => {
            if let Some(challenge) = challenge {
                tracing::warn!(
                    client_id = %ctx.client_id_for_error,
                    session_id = %session_id,
                    challenge_id = %challenge.id,
                    event = "stepup_challenge_issued",
                    request_id = %request_id,
                    "step-up challenge issued; fresh authentication required"
                );
            } else {
                tracing::warn!(
                    client_id = %ctx.client_id_for_error,
                    session_id = %session_id,
                    event = "stepup_challenge_issue_overflow",
                    request_id = %request_id,
                    "step-up challenge could not be issued because its expiry overflowed"
                );
            }
            Ok(false)
        }
        Err(err) => Err(stepup_store_operation_error_response(
            issuer_base,
            "advance",
            &err,
        )),
    }
}

pub(super) fn complete_authorize_stepup(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    decision: &AuthorizeDecision,
    session: &AuthorizeSessionState,
    issuer_base: &str,
) -> Result<(), Response> {
    if authorize_stepup_gate(state, ctx, decision, session, issuer_base)? {
        return Ok(());
    }
    Err(authorize_error_response(
        authorize_error_context(state, ctx, issuer_base),
        "login_required",
        Some("step-up authentication is required"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};

    fn request(max_age: Option<u64>, acr_values: Option<&str>) -> AuthzReq {
        AuthzReq {
            response_type: "code".to_string(),
            client_id: "stepup-client".to_string(),
            iss: None,
            redirect_uri: Some("https://client.example/callback".to_string()),
            resource: None,
            authorization_details: None,
            scope: Some("openid".to_string()),
            state: Some("state".to_string()),
            nonce: Some("nonce".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            request_uri: None,
            request_object: None,
            request_object_claims: None,
            acr_values: acr_values.map(ToString::to_string),
            max_age,
        }
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

    fn stepup_metric(event: &str) -> f64 {
        crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
            metrics
                .metrics
                .stepup_events
                .with_label_values(&[event])
                .get()
        })
        .unwrap_or(0.0)
    }

    #[test]
    fn stepup_request_id_uses_requested_acr_without_session_fallback() {
        let req = request(Some(0), Some("urn:mfa"));
        let requested = stepup_request_id(&req, Some("urn:mfa"), Some(0));
        let session_fallback = stepup_request_id(&req, Some("urn:pwd"), Some(0));
        assert_ne!(requested, session_fallback);
        assert_eq!(requested, stepup_request_id(&req, Some("urn:mfa"), Some(0)));
    }

    #[test]
    fn authorize_stepup_challenge_is_bound_consumed_and_replay_safe() {
        install_test_metrics();
        let store = crate::stepup::StepUpStore::new_process_local_with_ttl_for_tests(
            Duration::from_secs(60),
        );
        let issued_before = stepup_metric("challenge_issued");
        let consumed_before = stepup_metric("challenge_consumed");

        let outcome =
            try_advance_stepup_challenge(&store, "stepup-client", "old-session", "request-id", 100)
                .expect("challenge issue should succeed");
        let StepUpGateStoreOutcome::Issued(Some(challenge)) = outcome else {
            panic!("missing challenge should remain fail-closed");
        };
        assert_eq!(challenge.client_id, "stepup-client");
        assert_eq!(challenge.session_id, "old-session");
        assert_eq!(challenge.request_id, "request-id");

        assert!(store
            .try_complete_for_request("stepup-client", "old-session", "request-id", 101,)
            .expect("challenge completion should succeed")
            .is_some());
        assert!(matches!(
            try_advance_stepup_challenge(
                &store,
                "stepup-client",
                "old-session",
                "request-id",
                101,
            )
            .expect("challenge consumption should succeed"),
            StepUpGateStoreOutcome::Consumed
        ));
        assert!(!store
            .try_consume_completed("stepup-client", "old-session", "request-id", 101,)
            .expect("replay check should succeed"));
        assert!(stepup_metric("challenge_issued") >= issued_before + 1.0);
        assert!(stepup_metric("challenge_consumed") >= consumed_before + 1.0);
    }

    #[test]
    fn authorize_stepup_issue_overflow_remains_unsatisfied() {
        let store = crate::stepup::StepUpStore::new_process_local_with_ttl_for_tests(
            Duration::from_secs(60),
        );
        assert!(matches!(
            try_advance_stepup_challenge(
                &store,
                "stepup-client",
                "old-session",
                "request-id",
                u64::MAX,
            )
            .expect("overflow is a fail-closed outcome"),
            StepUpGateStoreOutcome::Issued(None)
        ));
    }
}
