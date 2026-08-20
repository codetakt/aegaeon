mod bind;

use super::super::super::configuration_documents::UPDATE_ENVIRONMENT_POLICY_SQL;
use super::super::super::{i32_from_u32_field, management_internal_error};
use crate::management::types::PolicyDocument;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn update_environment_policy_state(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.environment_policies (
  environment_id,
  configuration_version_id,
  pkce_required,
  dcr_enabled,
  allowed_signing_algorithms,
  allowed_grant_types,
  access_token_time_to_live_seconds,
  id_token_time_to_live_seconds,
  refresh_token_time_to_live_seconds,
  authorization_code_time_to_live_seconds
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (environment_id) DO NOTHING
        ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(policy.pkce_required)
    .bind(policy.dcr_enabled)
    .bind(policy.allowed_signing_algorithms.clone())
    .bind(policy.allowed_grant_types.clone())
    .bind(i32_from_u32_field(
        "access_token_time_to_live_seconds",
        policy.access_token_time_to_live_seconds,
        request_id,
    )?)
    .bind(i32_from_u32_field(
        "id_token_time_to_live_seconds",
        policy.id_token_time_to_live_seconds,
        request_id,
    )?)
    .bind(i32_from_u32_field(
        "refresh_token_time_to_live_seconds",
        policy.refresh_token_time_to_live_seconds,
        request_id,
    )?)
    .bind(i32_from_u32_field(
        "authorization_code_time_to_live_seconds",
        policy.authorization_code_time_to_live_seconds,
        request_id,
    )?)
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to prepare environment policy"))?;

    let result = bind::bind_policy_update_fields(
        sqlx::query(UPDATE_ENVIRONMENT_POLICY_SQL)
            .bind(environment_id)
            .bind(configuration_version_id),
        policy,
        request_id,
    )?
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to update environment policy"))?;
    if result.rows_affected() != 1 {
        return Err(management_internal_error(
            request_id,
            "Environment policy projection is missing",
        ));
    }

    Ok(())
}
