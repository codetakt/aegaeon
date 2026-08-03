use axum::response::Response;

use crate::util::constant_time_eq;

use super::super::hash_support::sha256_array;
use super::super::http_errors::forbidden;
use super::super::ManagementConfig;

pub(in crate::web::management) fn enforce_bootstrap_token(
    cfg: &ManagementConfig,
    provided_token: Option<&str>,
    request_id: &str,
) -> Result<(), Response> {
    let Some(expected) = cfg.bootstrap_token_sha256() else {
        return Err(forbidden(
            "bootstrap_token_unconfigured",
            "Management bootstrap token is not configured",
            request_id,
        ));
    };

    let provided = provided_token
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            forbidden(
                "bootstrap_token_required",
                "Bootstrap token required",
                request_id,
            )
        })?;

    let provided_hash = sha256_array(provided.as_bytes());
    if !constant_time_eq(expected, &provided_hash) {
        return Err(forbidden(
            "bootstrap_token_mismatch",
            "Bootstrap token did not match",
            request_id,
        ));
    }

    Ok(())
}
