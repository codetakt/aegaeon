use super::common::{inventory_fingerprint, user_runtime_store_error_response};
use crate::management::types::UserSessionInventoryEntry;
use crate::web::auth_session::AuthSession;
use crate::web::management::AppState;
use axum::response::Response;

pub(in crate::web::management) async fn collect_user_sessions(
    state: &AppState,
    subject: &str,
    query: &crate::web::management::PaginationQuery,
    request_id: &str,
) -> Result<crate::management::types::ListUserSessionsResponse, Response> {
    use crate::web::auth_session::SessionCursor;
    use crate::web::management::pagination::{
        encode_keyset_page_token, invalid_page_token_response, pagination_params,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let params = pagination_params(query, 2, request_id)?;
    let cursor = match (params.cursor_value(0), params.cursor_value(1)) {
        (Some(time), Some(digest)) => Some(SessionCursor {
            auth_time: time
                .parse::<i64>()
                .ok()
                .filter(|time| *time >= 0)
                .ok_or_else(|| invalid_page_token_response(request_id))?,
            digest: URL_SAFE_NO_PAD
                .decode(digest)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| invalid_page_token_response(request_id))?,
        }),
        (None, None) => None,
        _ => return Err(invalid_page_token_response(request_id)),
    };
    let page = state
        .browser_auth
        .auth_sessions
        .inventory_page(
            subject,
            cursor,
            usize::try_from(params.limit).map_err(|_| invalid_page_token_response(request_id))?,
        )
        .await
        .map_err(|error| {
            user_runtime_store_error_response(
                "auth session store",
                &error,
                "Session inventory store unavailable",
                request_id,
            )
        })?;
    let page_info = page.next.map(|cursor| crate::management::types::PageInfo {
        next_page_token: Some(encode_keyset_page_token([
            cursor.auth_time.to_string(),
            URL_SAFE_NO_PAD.encode(cursor.digest),
        ])),
    });
    Ok(crate::management::types::ListUserSessionsResponse {
        sessions: page
            .sessions
            .into_iter()
            .map(|(sid, session)| user_session_entry_from_store(&sid, &session))
            .collect(),
        page_info,
    })
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
        .find_inventory_session(subject, session_inventory_id)
        .await
        .map_err(|error| {
            user_runtime_store_error_response(
                "auth session store",
                &error,
                "Session inventory store unavailable",
                request_id,
            )
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
