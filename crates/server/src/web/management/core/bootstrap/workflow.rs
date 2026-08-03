use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

use crate::management::types::BootstrapOwnerRequest;

use super::super::super::{
    begin_management_transaction, commit_management_transaction, enforce_bootstrap_token,
    error_response, hash_password, insert_team_owner_membership, management_internal_error,
    normalize_email, validate_bootstrap_owner_password, ManagementConfig,
};
use super::persistence::{
    bootstrap_completed, insert_bootstrap_administrator, insert_bootstrap_audit_record,
    insert_bootstrap_team,
};

pub(super) async fn bootstrap_owner_inner(
    pool: &PgPool,
    cfg: &ManagementConfig,
    req: &BootstrapOwnerRequest,
    request_id: &str,
) -> Result<(), Response> {
    enforce_bootstrap_token(cfg, req.bootstrap_token.as_deref(), request_id)?;

    let Some(email) = normalize_email(&req.email) else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Email must be a valid address",
            None,
            Some(request_id),
        ));
    };

    let mut tx = begin_management_transaction(pool, request_id).await?;
    if sqlx::query("SELECT pg_advisory_xact_lock(724617523)")
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return Err(management_internal_error(
            request_id,
            "Failed to acquire bootstrap lock",
        ));
    }

    if bootstrap_completed(&mut tx, request_id).await? {
        return Err(error_response(
            StatusCode::CONFLICT,
            "bootstrap_completed",
            "Bootstrap has already been completed",
            None,
            Some(request_id),
        ));
    }

    if let Err(message) = validate_bootstrap_owner_password(&req.password) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            message,
            None,
            Some(request_id),
        ));
    }
    let password_hash = hash_password(&req.password)?;

    let administrator_id =
        insert_bootstrap_administrator(&mut tx, &email, &password_hash, request_id).await?;
    let team_id = insert_bootstrap_team(&mut tx, request_id).await?;
    insert_team_owner_membership(&mut tx, team_id, administrator_id, request_id).await?;
    insert_bootstrap_audit_record(&mut tx, team_id, administrator_id, &email, request_id).await?;
    commit_management_transaction(tx, request_id).await
}
