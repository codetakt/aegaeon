use axum::{
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use sqlx::PgPool;

use crate::web::cookie_value;

use super::super::{
    error_response, management_internal_error, management_single_header, state::ManagementSession,
    AppState, MGMT_SESSION_COOKIE_NAME,
};
use super::api_key::{authenticate_management_api_key, management_bearer_api_key};

pub(in crate::web::management) fn get_management_session_id(
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Option<String>, Response> {
    let cookie_header =
        management_single_header(headers, header::COOKIE.as_str(), "Cookie", request_id)?;
    Ok(cookie_header.and_then(|value| cookie_value(value, MGMT_SESSION_COOKIE_NAME)))
}

pub(in crate::web::management) async fn require_management_session_async(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<ManagementSession, Response> {
    let now_epoch_secs = super::super::super::now_epoch_secs()
        .map_err(|_| management_internal_error(request_id, "System clock unavailable"))?;
    let cookie_header =
        management_single_header(headers, header::COOKIE.as_str(), "Cookie", request_id)?;
    let bearer_api_key = management_bearer_api_key(headers, request_id)?;
    let session_id = cookie_header.and_then(|value| cookie_value(value, MGMT_SESSION_COOKIE_NAME));

    if bearer_api_key.is_some() && cookie_header.is_some() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Management API key requests must not include Cookie",
            None,
            Some(request_id),
        ));
    }

    if let Some(raw_api_key) = bearer_api_key {
        return authenticate_management_api_key(
            &state.db_pool,
            raw_api_key,
            now_epoch_secs,
            request_id,
        )
        .await;
    }

    let Some(sid) = session_id else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Session cookie or Bearer API key required",
            None,
            Some(request_id),
        ));
    };

    match state
        .management
        .sessions
        .try_get_async(sid, now_epoch_secs)
        .await
    {
        Ok(Some(session)) => {
            validate_human_management_session(&state.db_pool, session, request_id).await
        }
        Ok(None) => Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Session is invalid or expired",
            None,
            Some(request_id),
        )),
        Err(err) => {
            tracing::error!(
                error = %err,
                request_id,
                "management session store lookup failed"
            );
            Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "Session store unavailable",
                None,
                Some(request_id),
            ))
        }
    }
}

pub(in crate::web::management) async fn require_human_management_session_async(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<ManagementSession, Response> {
    let session = require_management_session_async(state, headers, request_id).await?;
    if session.is_human_session() {
        return Ok(session);
    }
    Err(error_response(
        StatusCode::FORBIDDEN,
        "forbidden",
        "This operation requires an interactive management session",
        None,
        Some(request_id),
    ))
}

async fn validate_human_management_session(
    pool: &PgPool,
    session: ManagementSession,
    request_id: &str,
) -> Result<ManagementSession, Response> {
    let row = sqlx::query(
        r"
SELECT 1
FROM aegaeon.administrators
WHERE id = $1
  AND status = 'ACTIVE'
  AND kind = 'HUMAN'
        ",
    )
    .bind(session.administrator_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Administrator status unavailable",
            None,
            Some(request_id),
        )
    })?;

    row.map(|_| session).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Session is invalid or expired",
            None,
            Some(request_id),
        )
    })
}
