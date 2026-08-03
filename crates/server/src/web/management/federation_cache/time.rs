use super::super::{error_response, management_internal_error};
use crate::util;
use axum::response::Response;
use http::StatusCode;

pub(in crate::web::management) fn duration_secs_i64(
    duration: std::time::Duration,
    request_id: &str,
) -> Result<i64, Response> {
    i64::try_from(duration.as_secs()).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Federation cache TTL is outside the supported range",
            None,
            Some(request_id),
        )
    })
}

pub(super) fn unix_epoch_now_i64(request_id: &str) -> Result<i64, Response> {
    util::now_unix_epoch_secs_i64().map_err(|err| {
        util::log_clock_error("management clock", &err);
        management_internal_error(request_id, "System clock is outside the supported range")
    })
}
