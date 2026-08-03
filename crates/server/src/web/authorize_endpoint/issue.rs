use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::authcode::types::AuthorizationRequest as AuthzReq;
use crate::authcode::{
    store::AuthorizationCodeOneTimeInputCommit, AuthorizationCodeIssueError,
    AuthorizationCodeIssueInput,
};
use crate::end_user_profiles;
#[cfg(test)]
use crate::par::authorize_with_par;
use crate::util;

use super::super::authorize_context::{authorize_request_object_deps, AuthorizeRequestContext};
#[cfg(test)]
use super::super::authorize_request::{enforce_request_object_jti, par_authorize_error_response};
use super::super::authorize_request::{
    request_object_jti_authorization_code_commit_context, request_object_resolution_error_response,
};
use super::super::oauth_audit::{require_oauth_audit, OAuthAuditEvent};
use super::super::oauth_errors::registry_state_error_response;
use super::super::profile_policy::record_downstream_profile_rejection;
use super::super::{
    authorize_error_response, no_cache_redirect_response, AppState, AuthorizeErrorContext,
};
use super::session::AuthorizeSessionState;

fn apply_set_cookie_header(response: &mut Response, set_cookie: Option<&str>) {
    let Some(set_cookie) = set_cookie else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(set_cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}

fn authorize_success_response(
    state: &AppState,
    response_mode: crate::form_post::ResponseMode,
    client_id_for_error: &str,
    state_for_echo: Option<&str>,
    code: &str,
    redirect_uri: &str,
    issuer_base: &str,
) -> Response {
    let redirect_uri_valid = if redirect_uri.is_empty() {
        false
    } else {
        match state
            .clients
            .try_validate_redirect_uri(client_id_for_error, redirect_uri)
        {
            Ok(valid) => valid,
            Err(error) => {
                return registry_state_error_response(
                    issuer_base,
                    "authorize_success_validate_redirect_uri",
                    error,
                );
            }
        }
    };
    if response_mode == crate::form_post::ResponseMode::FormPost && redirect_uri_valid {
        if let Ok(response) =
            crate::form_post::authorization_success(redirect_uri, code, state_for_echo, issuer_base)
        {
            return response;
        }
    }
    if state.cfg.strict_authorize_redirect
        && !redirect_uri.is_empty()
        && redirect_uri_valid
        && response_mode == crate::form_post::ResponseMode::Query
    {
        let url = util::append_code_and_state(redirect_uri, code, state_for_echo, issuer_base);
        return no_cache_redirect_response(&url);
    }
    let mut body = json!({ "code": code, "iss": issuer_base });
    if let Some(state_for_echo) = state_for_echo {
        body["state"] = json!(state_for_echo);
    }
    let mut response = (StatusCode::OK, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

fn authorize_error_request(ctx: &AuthorizeRequestContext) -> AuthzReq {
    AuthzReq {
        response_type: "code".to_string(),
        client_id: ctx.client_id_for_error.clone(),
        iss: None,
        redirect_uri: ctx.redirect_uri_for_error.clone(),
        resource: None,
        scope: None,
        state: ctx.state_for_echo.clone(),
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        authorization_details: None,
        acr_values: None,
        max_age: None,
    }
}

pub(super) fn authorize_error_context<'a>(
    state: &'a AppState,
    req: &'a AuthzReq,
    response_mode: crate::form_post::ResponseMode,
    issuer_base: &'a str,
    state_for_echo: Option<&'a str>,
) -> AuthorizeErrorContext<'a> {
    AuthorizeErrorContext::with_state_for_echo(
        state.cfg.as_ref(),
        state.clients.as_ref(),
        req,
        response_mode,
        issuer_base,
        state_for_echo,
    )
}

#[cfg(test)]
fn consume_authorize_par_request(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    issuer_base: &str,
) -> Result<(), Response> {
    let Some(request_uri) = ctx.req.request_uri.as_deref() else {
        return Ok(());
    };
    authorize_with_par(state.protocol.par_store.as_ref(), request_uri)
        .map(|_| ())
        .map_err(|err| par_authorize_error_response(issuer_base, &err))
}

#[cfg(test)]
fn consume_authorize_direct_request_object_jti(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    issuer_base: &str,
) -> Result<(), Response> {
    if ctx.req.request_uri.is_some() {
        return Ok(());
    }
    let Some(claims) = ctx.req.request_object_claims.as_ref() else {
        return Ok(());
    };
    let deps = authorize_request_object_deps(state);
    enforce_request_object_jti(&deps, &ctx.req.client_id, claims)
        .map_err(|err| request_object_resolution_error_response(issuer_base, &err))
}

#[cfg(test)]
fn consume_authorize_one_time_inputs(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    issuer_base: &str,
) -> Result<(), Response> {
    consume_authorize_par_request(state, ctx, issuer_base)?;
    consume_authorize_direct_request_object_jti(state, ctx, issuer_base)
}

struct AuthorizeOneTimeInputCommitPlan {
    redis: AuthorizationCodeOneTimeInputCommit,
    #[cfg(test)]
    process_local_preconsume: bool,
}

fn atomic_authorize_commit_required_response(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    issuer_base: &str,
    surface: &str,
) -> Response {
    authorize_error_response(
        authorize_error_context(
            state,
            &ctx.req,
            ctx.response_mode,
            issuer_base,
            ctx.state_for_echo.as_deref(),
        ),
        "server_error",
        Some(&format!(
            "{surface} store does not support atomic authorization-code commit"
        )),
    )
}

fn authorize_one_time_input_commit_plan(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    issuer_base: &str,
) -> Result<AuthorizeOneTimeInputCommitPlan, Response> {
    let mut redis = AuthorizationCodeOneTimeInputCommit::default();
    #[cfg(test)]
    let mut process_local_preconsume = false;

    if let Some(request_uri) = ctx.req.request_uri.as_deref() {
        let Some(expected_continuation) = ctx.par_authorize_continuation.as_deref() else {
            return Err(atomic_authorize_commit_required_response(
                state,
                ctx,
                issuer_base,
                "PAR continuation",
            ));
        };
        match state
            .protocol
            .par_store
            .authorization_code_commit_context(request_uri, expected_continuation)
        {
            Some(commit) => redis.par = Some(commit),
            None => {
                #[cfg(test)]
                {
                    process_local_preconsume = true;
                }
                #[cfg(not(test))]
                {
                    return Err(atomic_authorize_commit_required_response(
                        state,
                        ctx,
                        issuer_base,
                        "PAR request_uri",
                    ));
                }
            }
        }
    } else if let Some(claims) = ctx.req.request_object_claims.as_ref() {
        let deps = authorize_request_object_deps(state);
        match request_object_jti_authorization_code_commit_context(
            &deps,
            &ctx.req.client_id,
            claims,
        )
        .map_err(|err| request_object_resolution_error_response(issuer_base, &err))?
        {
            Some(commit) => redis.request_object_jti = Some(commit),
            None => {
                #[cfg(test)]
                {
                    process_local_preconsume = true;
                }
                #[cfg(not(test))]
                {
                    return Err(atomic_authorize_commit_required_response(
                        state,
                        ctx,
                        issuer_base,
                        "Request Object jti replay",
                    ));
                }
            }
        }
    }

    Ok(AuthorizeOneTimeInputCommitPlan {
        redis,
        #[cfg(test)]
        process_local_preconsume,
    })
}

async fn issue_authorize_code_response(
    state: &AppState,
    ctx: AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    local_profile: Option<end_user_profiles::OidcProfileClaims>,
    one_time_inputs: AuthorizationCodeOneTimeInputCommit,
    issuer_base: &str,
) -> Response {
    let error_request = authorize_error_request(&ctx);
    let response_mode = ctx.response_mode;
    let client_id_for_error = ctx.client_id_for_error.clone();
    let state_for_echo = ctx.state_for_echo.clone();
    let pkce_required = ctx.pkce_required;
    let profile_pkce_required = ctx.profile_pkce_required;
    match state
        .tokens
        .issuer
        .issue_authorization_code_with_local_profile_and_one_time_inputs_async(
            AuthorizationCodeIssueInput {
                acr: session.session_acr.clone(),
                auth_session_id: session.session_id.clone(),
                local_profile,
                claim_release_policy: session.claim_release_policy.clone(),
                ..AuthorizationCodeIssueInput::new(
                    ctx.req,
                    session.user_id.clone(),
                    pkce_required,
                    session.auth_time_epoch_secs,
                )
            },
            one_time_inputs,
        )
        .await
    {
        Ok((code, Some(redirect_uri))) => {
            let mut response = authorize_success_response(
                state,
                response_mode,
                &client_id_for_error,
                state_for_echo.as_deref(),
                &code,
                &redirect_uri,
                issuer_base,
            );
            apply_set_cookie_header(&mut response, session.set_cookie.as_deref());
            response
        }
        Ok((_, None)) => authorize_error_response(
            authorize_error_context(
                state,
                &error_request,
                response_mode,
                issuer_base,
                state_for_echo.as_deref(),
            ),
            "invalid_request",
            Some("redirect_uri is required for authorization response delivery"),
        ),
        Err(error) => {
            let (error_code, error_description, record_pkce_rejection) = match error {
                AuthorizationCodeIssueError::PkceRequired
                | AuthorizationCodeIssueError::PkceS256Required => (
                    "invalid_request",
                    "PKCE (S256) is required",
                    profile_pkce_required,
                ),
                AuthorizationCodeIssueError::PushedAuthorizationRequestMissing => (
                    "invalid_request_uri",
                    "pushed authorization request is missing or already consumed",
                    false,
                ),
                AuthorizationCodeIssueError::RequestObjectJtiReplay => (
                    "invalid_request",
                    "Request Object jti replay detected",
                    false,
                ),
                AuthorizationCodeIssueError::InvalidTarget(_) => {
                    ("invalid_target", "invalid resource indicator", false)
                }
                AuthorizationCodeIssueError::StoreUnavailable(_)
                | AuthorizationCodeIssueError::ClockBeforeUnixEpoch => (
                    "server_error",
                    "authorization-code storage is unavailable",
                    false,
                ),
                AuthorizationCodeIssueError::OpenIdAuthSessionRequired
                | AuthorizationCodeIssueError::NonceRequired
                | AuthorizationCodeIssueError::OpenIdDisabled
                | AuthorizationCodeIssueError::StateUsed
                | AuthorizationCodeIssueError::NonceUsed
                | AuthorizationCodeIssueError::CodeCollision
                | AuthorizationCodeIssueError::CodeExpired => (
                    "access_denied",
                    "authorization denied or verification failed",
                    false,
                ),
            };
            if record_pkce_rejection {
                record_downstream_profile_rejection("pkce_required", "authorize");
            }
            authorize_error_response(
                authorize_error_context(
                    state,
                    &error_request,
                    response_mode,
                    issuer_base,
                    state_for_echo.as_deref(),
                ),
                error_code,
                Some(error_description),
            )
        }
    }
}

async fn audit_authorize_code_issue_approval(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    issuer_base: &str,
) -> Result<(), Response> {
    require_oauth_audit(
        state,
        issuer_base,
        OAuthAuditEvent {
            event_type: "oauth.authorization_code.issue.approved.v1",
            category: "authorization",
            outcome: "approved",
            severity: "info",
            actor_type: "end_user",
            actor_id: Some(session.user_id.as_str()),
            target_type: "client",
            target_id: Some(ctx.req.client_id.as_str()),
            request_id: ctx.request_id.as_str(),
            data: json!({
                "phase": "pre_commit",
                "responseType": ctx.req.response_type.as_str(),
                "scope": ctx.req.scope.as_deref(),
                "resource": ctx.req.resource.as_deref(),
                "responseMode": format!("{:?}", ctx.response_mode),
                "pkceRequired": ctx.pkce_required
            }),
        },
    )
    .await
}

pub(super) async fn commit_authorize_code_response(
    state: &AppState,
    ctx: AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    local_profile: Option<end_user_profiles::OidcProfileClaims>,
    issuer_base: &str,
) -> Response {
    if let Err(response) =
        audit_authorize_code_issue_approval(state, &ctx, session, issuer_base).await
    {
        return response;
    }
    let one_time_inputs = match authorize_one_time_input_commit_plan(state, &ctx, issuer_base) {
        Ok(plan) => {
            #[cfg(test)]
            if plan.process_local_preconsume {
                if let Err(response) = consume_authorize_one_time_inputs(state, &ctx, issuer_base) {
                    return response;
                }
            }
            plan.redis
        }
        Err(response) => return response,
    };
    issue_authorize_code_response(
        state,
        ctx,
        session,
        local_profile,
        one_time_inputs,
        issuer_base,
    )
    .await
}
