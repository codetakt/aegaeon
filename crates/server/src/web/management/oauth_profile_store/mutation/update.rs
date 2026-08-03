use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::{management_internal_error, oauth_profiles_support::OAuthProfileInput};

pub(in crate::web::management) async fn update_oauth_profile_row(
    tx: &mut Transaction<'_, Postgres>,
    oauth_profile_id: Uuid,
    environment_id: Uuid,
    input: &OAuthProfileInput,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
UPDATE aegaeon.oauth_profiles
SET
  name = $3,
  description = $4,
  profile_type = $5::aegaeon.oauth_profile_type,
  is_default = $6,
  require_pkce = $7,
  require_state_parameter = $8,
  require_iss_parameter = $9,
  sender_constrained = $10::aegaeon.oauth_sender_constraint,
  enforce_refresh_sender_binding = $11,
  allowed_grant_types = $12,
  token_endpoint_auth_methods_allowed = $13,
  expires_at = $14::timestamptz,
  updated_at = now()
WHERE id = $1
  AND environment_id = $2
  AND status <> 'RETIRED'
RETURNING
  id,
  environment_id,
  configuration_version_id,
  name,
  description,
  profile_type::text AS profile_type,
  is_default,
  require_pkce,
  require_state_parameter,
  require_iss_parameter,
  sender_constrained::text AS sender_constrained,
  enforce_refresh_sender_binding,
  allowed_grant_types,
  token_endpoint_auth_methods_allowed,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS expires_at,
  status::text AS status,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS updated_at
        "#,
    )
    .bind(oauth_profile_id)
    .bind(environment_id)
    .bind(&input.name)
    .bind(&input.description)
    .bind(&input.profile_type)
    .bind(input.is_default)
    .bind(input.require_pkce)
    .bind(input.require_state_parameter)
    .bind(input.require_iss_parameter)
    .bind(&input.sender_constrained)
    .bind(input.enforce_refresh_sender_binding)
    .bind(input.allowed_grant_types.clone())
    .bind(input.token_endpoint_auth_methods_allowed.clone())
    .bind(&input.expires_at)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to update oauth profile"))
}
