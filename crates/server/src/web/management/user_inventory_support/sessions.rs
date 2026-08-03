use super::common::{inventory_fingerprint, user_runtime_store_error_response};
use crate::management::types::UserSessionInventoryEntry;
use crate::web::auth_session::AuthSession;
use crate::web::management::AppState;
use axum::response::Response;

pub(in crate::web::management) async fn collect_user_sessions(
    state: &AppState,
    subject: &str,
    request_id: &str,
) -> Result<Vec<UserSessionInventoryEntry>, Response> {
    let mut sessions = state
        .browser_auth
        .auth_sessions
        .try_list_for_user_async(subject.to_string())
        .await
        .map_err(|err| {
            user_runtime_store_error_response(
                "auth session store",
                &err,
                "Session inventory store unavailable",
                request_id,
            )
        })?
        .into_iter()
        .map(|(session_id, session)| user_session_entry_from_store(&session_id, &session))
        .collect::<Vec<_>>();
    sessions.sort_by(|left, right| {
        right
            .auth_time_epoch_seconds
            .cmp(&left.auth_time_epoch_seconds)
    });
    Ok(sessions)
}

pub(in crate::web::management) async fn find_user_session_raw_id(
    state: &AppState,
    subject: &str,
    session_inventory_id: &str,
    request_id: &str,
) -> Result<Option<String>, Response> {
    state
        .browser_auth
        .auth_sessions
        .try_list_for_user_async(subject.to_string())
        .await
        .map_err(|err| {
            user_runtime_store_error_response(
                "auth session store",
                &err,
                "Session inventory store unavailable",
                request_id,
            )
        })
        .map(|sessions| {
            sessions.into_iter().find_map(|(session_id, _)| {
                (inventory_fingerprint(&session_id) == session_inventory_id).then_some(session_id)
            })
        })
}

fn user_session_entry_from_store(
    session_id: &str,
    session: &AuthSession,
) -> UserSessionInventoryEntry {
    UserSessionInventoryEntry {
        id: inventory_fingerprint(session_id),
        auth_time_epoch_seconds: session.auth_time_epoch_secs.cast_signed(),
        acr: session.acr.clone(),
    }
}
