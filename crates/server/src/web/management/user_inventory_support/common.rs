use crate::util;
use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};
use std::time::SystemTime;

pub(in crate::web::management::user_inventory_support) fn inventory_fingerprint(
    raw: &str,
) -> String {
    aegaeon_crypto::hash::sha256_hex(raw.as_bytes())
}

pub(in crate::web::management::user_inventory_support) fn seconds_since_epoch(
    value: SystemTime,
) -> Option<i64> {
    util::unix_epoch_secs_i64(value)
        .inspect_err(|err| {
            util::log_clock_error("management stored timestamp", err);
        })
        .ok()
}

pub(in crate::web::management) fn user_runtime_store_error_response(
    store: &str,
    error: &str,
    description: &str,
    request_id: &str,
) -> Response {
    tracing::error!(
        store,
        error,
        request_id,
        "user runtime store operation failed"
    );
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        description,
        None,
        Some(request_id),
    )
}
