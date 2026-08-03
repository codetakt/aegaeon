use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::management_internal_error;

#[derive(Clone, Debug)]
pub(in crate::web::management) struct RetirableOAuthProfile {
    pub(in crate::web::management) profile_id: Uuid,
    pub(in crate::web::management) configuration_version_id: Uuid,
    pub(in crate::web::management) name: String,
    pub(in crate::web::management) profile_type: String,
    pub(in crate::web::management) is_default: bool,
    pub(in crate::web::management) expires_at: Option<String>,
}

pub(in crate::web::management) async fn load_retirable_oauth_profile(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    oauth_profile_id: Uuid,
    request_id: &str,
) -> Result<Option<RetirableOAuthProfile>, Response> {
    let row = sqlx::query(
        r#"
SELECT
  id,
  configuration_version_id,
  name,
  profile_type::text AS profile_type,
  is_default,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
FROM aegaeon.oauth_profiles
WHERE id = $1
  AND environment_id = $2
  AND status <> 'RETIRED'
        "#,
    )
    .bind(oauth_profile_id)
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let profile_id = row
        .try_get("id")
        .map_err(|_| management_internal_error(request_id, "Failed to read oauth profile row"))?;
    let configuration_version_id = row
        .try_get("configuration_version_id")
        .map_err(|_| management_internal_error(request_id, "Failed to read oauth profile row"))?;
    let name = row
        .try_get("name")
        .map_err(|_| management_internal_error(request_id, "Failed to read oauth profile row"))?;
    let profile_type = row
        .try_get("profile_type")
        .map_err(|_| management_internal_error(request_id, "Failed to read oauth profile row"))?;
    let is_default = row
        .try_get("is_default")
        .map_err(|_| management_internal_error(request_id, "Failed to read oauth profile row"))?;
    let expires_at = row
        .try_get("expires_at")
        .map_err(|_| management_internal_error(request_id, "Failed to read oauth profile row"))?;

    Ok(Some(RetirableOAuthProfile {
        profile_id,
        configuration_version_id,
        name,
        profile_type,
        is_default,
        expires_at,
    }))
}

pub(in crate::web::management) async fn retire_oauth_profile(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    oauth_profile_id: Uuid,
    request_id: &str,
) -> Result<u64, Response> {
    let result = sqlx::query(
        r"
UPDATE aegaeon.oauth_profiles
SET status = 'RETIRED', is_default = false, deleted_at = now(), updated_at = now()
WHERE id = $1
  AND environment_id = $2
  AND status <> 'RETIRED'
        ",
    )
    .bind(oauth_profile_id)
    .bind(environment_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to delete oauth profile"))?;

    Ok(result.rows_affected())
}
