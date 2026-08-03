use super::super::super::{error_response, management_internal_error};
use super::ClientOAuthProfileChange;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn validate_client_oauth_profile_change(
    pool: &PgPool,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    oauth_profile_change: Option<ClientOAuthProfileChange>,
    request_id: &str,
) -> Result<(), Response> {
    let Some(oauth_profile_change) = oauth_profile_change else {
        return Ok(());
    };

    match oauth_profile_change {
        ClientOAuthProfileChange::Assign(profile_id) => {
            let profile_row = sqlx::query(
                r"
SELECT id
FROM aegaeon.oauth_profiles
WHERE id = $1
  AND environment_id = $2
  AND configuration_version_id = $3
  AND profile_type = 'DOWNSTREAM'
  AND status = 'ACTIVE'
  AND (expires_at IS NULL OR expires_at > now())
                ",
            )
            .bind(profile_id)
            .bind(environment_id)
            .bind(configuration_version_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

            if profile_row.is_none() {
                return Err(error_response(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "OAuth profile not found or inactive",
                    None,
                    Some(request_id),
                ));
            }
        }
        ClientOAuthProfileChange::Clear => {
            let default_row = sqlx::query(
                r"
SELECT id
FROM aegaeon.oauth_profiles
WHERE environment_id = $1
  AND configuration_version_id = $2
  AND profile_type = 'DOWNSTREAM'
  AND is_default = true
  AND status = 'ACTIVE'
  AND (expires_at IS NULL OR expires_at > now())
LIMIT 1
                ",
            )
            .bind(environment_id)
            .bind(configuration_version_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

            if default_row.is_none() {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Default downstream OAuth profile is required when clearing oauthProfileId",
                    None,
                    Some(request_id),
                ));
            }
        }
    }

    Ok(())
}
