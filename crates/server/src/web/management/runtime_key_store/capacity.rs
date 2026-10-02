use super::super::runtime_keys::RuntimeKeyUsageInput;
use super::super::{error_response, management_internal_error};
use crate::runtime_keys::MAX_RETIRING_KEYS_PER_USAGE;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// The caller must hold this environment's row lock through retirement and commit.
/// This serializes the prospective count with every managed key lifecycle writer.
/// Use transaction time, as the runtime loader and retirement update do. Expiry
/// while waiting for the lock may conservatively require a new transaction.
pub(super) async fn ensure_retirement_capacity(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    usage: RuntimeKeyUsageInput,
    algorithm: &str,
    request_id: &str,
) -> Result<(), Response> {
    let (live, has_active): (i64, bool) = sqlx::query_as(
        r"
SELECT
  count(*) FILTER (WHERE status = 'RETIRING' AND retiring_expires_at > now()),
  count(*) FILTER (WHERE status = 'ACTIVE' AND algorithm = $3) > 0
FROM aegaeon.runtime_keys
WHERE environment_id = $1 AND usage = $2::aegaeon.runtime_key_usage
        ",
    )
    .bind(environment_id)
    .bind(usage.as_db_str())
    .bind(algorithm)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to check runtime key capacity"))?;
    let live = usize::try_from(live)
        .map_err(|_| management_internal_error(request_id, "Invalid runtime key count"))?;
    let prospective = live
        .checked_add(usize::from(has_active))
        .ok_or_else(|| management_internal_error(request_id, "Runtime key count overflow"))?;
    if prospective > MAX_RETIRING_KEYS_PER_USAGE {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Runtime key rotation exceeds retiring key capacity",
            Some(serde_json::json!({
                "usage": usage.as_db_str(),
                "liveRetiringCount": live,
                "prospectiveRetiringCount": prospective,
                "limit": MAX_RETIRING_KEYS_PER_USAGE,
            })),
            Some(request_id),
        ));
    }
    Ok(())
}
