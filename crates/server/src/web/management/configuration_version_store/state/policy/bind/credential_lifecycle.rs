use super::{i32_from_u32_field, PolicyUpdateQuery};
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(super) fn bind_credential_lifecycle_policy<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    Ok(query
        .bind(i32_from_u32_field(
            "activation_token_default_ttl_seconds",
            policy.activation_token_default_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "password_reset_token_default_ttl_seconds",
            policy.password_reset_token_default_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "recovery_token_max_ttl_seconds",
            policy.recovery_token_max_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "client_secret_default_expiration_days",
            policy.client_secret_default_expiration_days,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "client_secret_max_expiration_days",
            policy.client_secret_max_expiration_days,
            request_id,
        )?))
}
