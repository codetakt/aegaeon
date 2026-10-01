use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{error_response, management_internal_error};
use crate::management::types::PolicyDocument;
use crate::policy::scope_boundary::{policy_violations, ScopeViolation};

pub(super) fn require_valid_scopes(
    violations: &[ScopeViolation],
    request_id: &str,
) -> Result<(), Response> {
    let Some(first) = violations.first() else {
        return Ok(());
    };
    Err(error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        &first.to_string(),
        Some(serde_json::json!({"scopeViolations": violations})),
        Some(request_id),
    ))
}

pub(super) async fn validate_policy_scopes(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    active_version: Uuid,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    let violations = policy_violations(
        tx,
        environment,
        active_version,
        &policy.token_exchange,
        &policy.client_credentials,
    )
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to validate target rule scopes"))?;
    require_valid_scopes(&violations, request_id)
}
