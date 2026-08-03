use super::super::super::management_internal_error;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management::federation_logout_recovery) async fn clear_federation_logout_recovery_incident_status(
    tx: &mut Transaction<'_, Postgres>,
    incident_id: Uuid,
    reason: &str,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
UPDATE aegaeon.federation_logout_recovery_incidents
SET
  status = 'operator_cleared',
  failure_reason = $2,
  resolved_at = now()
WHERE id = $1
        ",
    )
    .bind(incident_id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| management_internal_error(request_id, "Failed to clear incident"))
}
