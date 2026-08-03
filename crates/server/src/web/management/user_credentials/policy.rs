use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::local_credentials::RecoveryTokenTtlPolicy;

use super::super::{
    configuration_version_store::load_environment_policy_document_in_transaction,
    management_internal_error,
};

pub(super) async fn load_recovery_token_ttl_policy_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    request_id: &str,
) -> Result<RecoveryTokenTtlPolicy, Response> {
    let policy =
        load_environment_policy_document_in_transaction(tx, environment_id, request_id).await?;
    RecoveryTokenTtlPolicy::new(
        i64::from(policy.activation_token_default_ttl_seconds),
        i64::from(policy.password_reset_token_default_ttl_seconds),
        i64::from(policy.recovery_token_max_ttl_seconds),
    )
    .map_err(|_| {
        management_internal_error(
            request_id,
            "Environment recovery token lifecycle policy is invalid",
        )
    })
}
