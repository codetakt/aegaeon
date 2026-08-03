use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::{management_internal_error, oauth_profiles_support::OAuthProfileInput};

pub(in crate::web::management) async fn insert_oauth_profile_row(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    input: &OAuthProfileInput,
    request_id: &str,
) -> Result<PgRow, Response> {
    sqlx::query(
        r#"
INSERT INTO aegaeon.oauth_profiles (
  environment_id,
  configuration_version_id,
  name,
  description,
  profile_type,
  is_default,
  require_pkce,
  require_state_parameter,
  require_iss_parameter,
  sender_constrained,
  enforce_refresh_sender_binding,
  allowed_grant_types,
  token_endpoint_auth_methods_allowed,
  expires_at
)
VALUES (
  $1,
  $2,
  $3,
  $4,
  $5::aegaeon.oauth_profile_type,
  $6,
  $7,
  $8,
  $9,
  $10::aegaeon.oauth_sender_constraint,
  $11,
  $12,
  $13,
  $14::timestamptz
)
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
    .bind(environment_id)
    .bind(configuration_version_id)
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
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to create oauth profile"))
}
