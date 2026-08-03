use crate::oidc::OidcLogoutEvent;
use crate::web::logout_dispatch::dispatch_backchannel_logout_if_enabled;
use crate::web::management::user_inventory_support::user_runtime_store_error_response;
use crate::web::management::AppState;
use axum::response::Response;

pub(super) async fn logout_oidc_session_for_auth_session(
    state: &AppState,
    auth_session_id: &str,
    request_id: &str,
) -> Result<Vec<OidcLogoutEvent>, Response> {
    let Some(sessions) = state.oidc.sessions.as_ref() else {
        return Ok(Vec::new());
    };
    sessions
        .try_logout_by_auth_session_id_async(auth_session_id.to_string())
        .await
        .map(|event| event.into_iter().collect())
        .map_err(|err| {
            user_runtime_store_error_response(
                "OIDC session store",
                &err,
                "OIDC session revocation store unavailable; operation not fully confirmed",
                request_id,
            )
        })
}

pub(super) async fn logout_oidc_sessions_for_user(
    state: &AppState,
    subject: &str,
    request_id: &str,
) -> Result<Vec<OidcLogoutEvent>, Response> {
    let Some(sessions) = state.oidc.sessions.as_ref() else {
        return Ok(Vec::new());
    };
    sessions
        .try_logout_by_user_async(subject.to_string())
        .await
        .map_err(|err| {
            user_runtime_store_error_response(
                "OIDC session store",
                &err,
                "OIDC session invalidation store unavailable; operation not fully confirmed",
                request_id,
            )
        })
}

pub(super) async fn dispatch_oidc_logout_events(
    state: &AppState,
    logout_events: Vec<OidcLogoutEvent>,
) {
    if let Some(cfg) = state.oidc.config.as_ref() {
        dispatch_backchannel_logout_if_enabled(state, cfg, logout_events).await;
    }
}
