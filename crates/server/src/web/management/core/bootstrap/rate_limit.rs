use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use std::net::SocketAddr;

use crate::management::types::BootstrapOwnerRequest;
use crate::web::management::{
    error_response, management_bootstrap_rate_limit_keys_for_subject,
    management_login_rate_limit_allows_async, management_transport_rejection, AppState,
};

pub(in crate::web::management::core::bootstrap) async fn enforce_bootstrap_rate_limit(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    req: &BootstrapOwnerRequest,
    request_id: &str,
) -> Result<(), Response> {
    let subject = state
        .transport
        .rate_limit_subject(Some(remote), headers)
        .map_err(|kind| management_transport_rejection(kind, request_id))?;
    let rate_limit_keys = management_bootstrap_rate_limit_keys_for_subject(
        &subject,
        &req.email,
        req.bootstrap_token.as_deref(),
    );
    match management_login_rate_limit_allows_async(
        state.management.login_rate_limiter.clone(),
        rate_limit_keys.to_vec(),
    )
    .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many bootstrap attempts",
            None,
            Some(request_id),
        )),
        Err(err) => {
            tracing::error!(
                error = %err,
                request_id = %request_id,
                "management bootstrap rate limiter unavailable"
            );
            Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "Rate limiter unavailable",
                None,
                Some(request_id),
            ))
        }
    }
}
