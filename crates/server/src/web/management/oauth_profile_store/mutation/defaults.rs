use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::super::super::management_internal_error;

pub(in crate::web::management) async fn clear_default_oauth_profiles(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    profile_type: &str,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
UPDATE aegaeon.oauth_profiles
SET is_default = false, updated_at = now()
WHERE environment_id = $1
  AND configuration_version_id = $2
  AND profile_type = $3::aegaeon.oauth_profile_type
  AND status = 'ACTIVE'
  AND is_default = true
        ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(profile_type)
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to clear default oauth profiles"))?;

    Ok(())
}
