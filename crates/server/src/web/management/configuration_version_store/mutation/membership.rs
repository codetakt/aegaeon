use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::super::super::{error_response, management_internal_error};

/// Carry effective memberships, not historical configuration snapshots. These
/// objects have stable IDs and are managed independently of the document. The
/// caller holds the environment lock and commits this with the active pointer.
pub(super) async fn carry_configuration_membership(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    previous_version: Uuid,
    next_version: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    if previous_version == next_version {
        return Ok(());
    }
    let occupied: bool = sqlx::query_scalar(
        r"
SELECT EXISTS (
  SELECT 1 FROM aegaeon.clients
  WHERE environment_id = $1 AND configuration_version_id = $2 AND status = 'ACTIVE'
  UNION ALL
  SELECT 1 FROM aegaeon.oauth_profiles
  WHERE environment_id = $1 AND configuration_version_id = $2 AND status = 'ACTIVE'
  UNION ALL
  SELECT 1 FROM aegaeon.connections
  WHERE environment_id = $1 AND configuration_version_id = $2
    AND status IN ('ACTIVE', 'DISABLED')
)
        ",
    )
    .bind(environment_id)
    .bind(next_version)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        management_internal_error(request_id, "Failed to check configuration membership")
    })?;
    if occupied {
        return Err(error_response(
            StatusCode::CONFLICT,
            "configuration_membership_conflict",
            "Target configuration version already has live memberships",
            None,
            Some(request_id),
        ));
    }

    // Preserve expiry, disabled/deleted state, payloads and credentials. Runtime
    // key/secret version IDs are provenance; their lifecycle-based readers do
    // not require active-version equality and those rows must not be moved.
    for statement in [
        "UPDATE aegaeon.clients SET configuration_version_id = $3
         WHERE environment_id = $1 AND configuration_version_id = $2 AND status = 'ACTIVE'",
        "UPDATE aegaeon.oauth_profiles SET configuration_version_id = $3
         WHERE environment_id = $1 AND configuration_version_id = $2 AND status = 'ACTIVE'",
        "UPDATE aegaeon.connections SET configuration_version_id = $3
         WHERE environment_id = $1 AND configuration_version_id = $2
           AND status IN ('ACTIVE', 'DISABLED')",
    ] {
        sqlx::query(statement)
            .bind(environment_id)
            .bind(previous_version)
            .bind(next_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| {
                management_internal_error(request_id, "Failed to carry configuration membership")
            })?;
    }
    Ok(())
}
