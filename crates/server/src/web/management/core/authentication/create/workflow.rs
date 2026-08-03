mod rate_limit;
mod session_response;

use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use std::net::SocketAddr;

use crate::management::types::CreateSessionRequest;
use crate::web::management::{
    error_response, management_db_pool, normalize_email, verify_password_or_dummy, AppState,
};

use super::super::persistence::{load_management_login_record, update_management_login_state};
use rate_limit::enforce_login_rate_limit;
use session_response::create_management_session_response;

pub(in crate::web::management::core::authentication::create) async fn create_authentication_session_response(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    req: &CreateSessionRequest,
    request_id: &str,
) -> Response {
    let pool = match management_db_pool(state, request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };

    let Some(email) = normalize_email(&req.email) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Email must be a valid address",
            None,
            Some(request_id),
        );
    };
    if let Err(resp) = enforce_login_rate_limit(state, remote, headers, &email, request_id).await {
        return resp;
    }
    let record = match load_management_login_record(pool, &email, request_id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            let _ = verify_password_or_dummy(&req.password, None);
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid email or password",
                None,
                Some(request_id),
            );
        }
        Err(resp) => return resp,
    };

    let password_ok = verify_password_or_dummy(&req.password, Some(&record.password_hash));
    if record.status != "ACTIVE" || !password_ok {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid email or password",
            None,
            Some(request_id),
        );
    }

    match update_management_login_state(
        pool,
        record.administrator_id,
        &record.password_hash,
        request_id,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid email or password",
                None,
                Some(request_id),
            );
        }
        Err(resp) => return resp,
    }

    create_management_session_response(state, record.administrator_id, request_id).await
}
