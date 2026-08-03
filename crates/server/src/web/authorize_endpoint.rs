mod issue;
mod session;

use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::HeaderMap,
    response::Response,
};
use std::net::SocketAddr;

use crate::end_user_profiles;
use crate::util;

use issue::{authorize_error_context, commit_authorize_code_response};

use super::authorize_context::build_authorize_request_context;
use super::authorize_login_redirect::authorize_login_redirect_response;
use super::request_admission::enforce_no_credentials_in_authorize_uri;
use super::{authorize_error_response, request_id_from_headers, transport_rejection, AppState};
use session::{
    authorize_decide_session, complete_authorize_stepup, resolve_authorize_session_state,
};

pub(in crate::web) use session::{authorize_requested_max_age, stepup_request_id};

async fn load_authorize_local_profile(
    state: &AppState,
    user_id: &str,
) -> Result<Option<end_user_profiles::OidcProfileClaims>, sqlx::Error> {
    let profile = end_user_profiles::load_user_profile_for_subject(
        &state.db_pool,
        state.issuer.as_str(),
        user_id,
    )
    .await
    .map(|record| {
        record.map(|record| end_user_profiles::oidc_profile_claims_from_record(&record))
    })?;
    Ok(profile)
}

pub(super) async fn authorize(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }
    if let Err(resp) = enforce_no_credentials_in_authorize_uri(&uri, issuer_base) {
        return resp;
    }
    let request_id = request_id_from_headers(&headers);
    let ctx = match build_authorize_request_context(&state, &uri, issuer_base, request_id).await {
        Ok(ctx) => ctx,
        Err(mut response) => {
            util::apply_no_cache_headers(&mut response);
            return response;
        }
    };
    let decision = match authorize_decide_session(&state, &headers, &ctx, issuer_base).await {
        Ok(decision) => decision,
        Err(mut response) => {
            util::apply_no_cache_headers(&mut response);
            return response;
        }
    };
    let mut resolved_session = None;
    if decision.stepup_required && decision.current_session.is_some() {
        let session = match resolve_authorize_session_state(&decision, issuer_base).await {
            Ok(session) => session,
            Err(mut response) => {
                util::apply_no_cache_headers(&mut response);
                return response;
            }
        };
        match complete_authorize_stepup(&state, &ctx, &decision, &session, issuer_base) {
            Ok(()) => resolved_session = Some(session),
            Err(mut response) if response.status().is_server_error() => {
                util::apply_no_cache_headers(&mut response);
                return response;
            }
            Err(mut response) => {
                // Unmet step-up must never reach code issuance. Today
                // `stepup_required` implies `needs_login`, so the login
                // redirect below handles this arm; if that implication is
                // ever broken, fail closed here instead of proceeding.
                if !decision.needs_login {
                    util::apply_no_cache_headers(&mut response);
                    return response;
                }
            }
        }
    }
    if decision.needs_login && resolved_session.is_none() {
        return authorize_login_redirect_response(
            &state,
            &ctx,
            &uri,
            decision.selected_acr.as_deref(),
            issuer_base,
        )
        .await;
    }
    let session = match resolved_session {
        Some(session) => session,
        None => match resolve_authorize_session_state(&decision, issuer_base).await {
            Ok(session) => session,
            Err(mut response) => {
                util::apply_no_cache_headers(&mut response);
                return response;
            }
        },
    };
    if !decision.stepup_required {
        if let Err(response) =
            complete_authorize_stepup(&state, &ctx, &decision, &session, issuer_base)
        {
            let mut response = response;
            util::apply_no_cache_headers(&mut response);
            return response;
        }
    }
    let local_profile = match load_authorize_local_profile(&state, &session.user_id).await {
        Ok(profile) => profile,
        Err(_) => {
            return authorize_error_response(
                authorize_error_context(
                    &state,
                    &ctx.req,
                    ctx.response_mode,
                    issuer_base,
                    ctx.state_for_echo.as_deref(),
                ),
                "server_error",
                Some("failed to load local profile"),
            );
        }
    };
    commit_authorize_code_response(&state, ctx, &session, local_profile, issuer_base).await
}
