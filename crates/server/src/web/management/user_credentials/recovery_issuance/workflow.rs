use super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    load_managed_user_identity_for_update, write_user_management_audit_event, EndUserAuditEvent,
    UserManagementContext,
};
use super::super::environment::load_environment_issuer_url;
use super::super::policy::load_recovery_token_ttl_policy_in_transaction;
use super::super::responses::load_issued_recovery_token_response_required;
use super::issue_recovery_token_with_redeem_url;
use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::management::types::{IssueRecoveryTokenRequest, IssueRecoveryTokenResponse};
use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

pub(super) async fn issue_recovery_token_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    body: &IssueRecoveryTokenRequest,
    purpose: RecoveryTokenPurpose,
    request_id: &str,
) -> Result<IssueRecoveryTokenResponse, Response> {
    let issuer_url = load_environment_issuer_url(
        &context.pool,
        context.team_id,
        context.environment_id,
        request_id,
    )
    .await?;
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let identity = load_managed_user_identity_for_update(
        &mut tx,
        context.team_id,
        context.environment_id,
        user_id,
        request_id,
    )
    .await?;
    let invalid_state_message = match purpose {
        RecoveryTokenPurpose::Activation => {
            "Activation tokens can only be issued for invited users"
        }
        RecoveryTokenPurpose::PasswordReset => {
            "Password reset tokens can only be issued for active users"
        }
    };
    let allowed_status = match purpose {
        RecoveryTokenPurpose::Activation => "INVITED",
        RecoveryTokenPurpose::PasswordReset => "ACTIVE",
    };
    if identity.status != allowed_status {
        return Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            invalid_state_message,
            None,
            Some(request_id),
        ));
    }

    let ttl_policy =
        load_recovery_token_ttl_policy_in_transaction(&mut tx, context.environment_id, request_id)
            .await?;
    let expires_in_secs = local_credentials::sanitize_recovery_token_ttl(
        body.expires_in_seconds,
        purpose,
        ttl_policy,
    )
    .map_err(|message| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            message,
            None,
            Some(request_id),
        )
    })?;
    let (issued, redeem_url) = issue_recovery_token_with_redeem_url(
        &mut tx,
        &issuer_url,
        user_id,
        purpose,
        expires_in_secs,
        context.session.administrator_id,
        request_id,
    )
    .await?;
    let event_type = match purpose {
        RecoveryTokenPurpose::Activation => "management.user.activationToken.issued.v1",
        RecoveryTokenPurpose::PasswordReset => "management.user.passwordResetToken.issued.v1",
    };
    write_user_management_audit_event(
        &mut tx,
        context,
        request_id,
        EndUserAuditEvent {
            event_type,
            target_id: user_id,
            data: serde_json::json!({
                "userId": user_id.to_string(),
                "subject": &identity.subject,
                "email": &identity.email,
                "purpose": issued.purpose.as_audit_label(),
                "tokenId": issued.id,
                "expiresAt": issued.expires_at,
            }),
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    load_issued_recovery_token_response_required(
        &context.pool,
        user_id,
        issued,
        redeem_url,
        request_id,
    )
    .await
}
