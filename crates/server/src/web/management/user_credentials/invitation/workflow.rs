use super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    insert_invited_user, normalize_optional_email, normalize_required_subject,
    write_user_management_audit_event, EndUserAuditEvent, UserManagementContext,
};
use super::super::environment::load_environment_issuer_url;
use super::super::policy::load_recovery_token_ttl_policy_in_transaction;
use super::super::recovery_issuance::issue_recovery_token_with_redeem_url;
use super::super::responses::load_issued_recovery_token_response_required;
use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::management::types::{InviteUserRequest, InviteUserResponse};
use axum::{http::StatusCode, response::Response};

pub(super) async fn invite_user_inner(
    context: &UserManagementContext,
    body: &InviteUserRequest,
    request_id: &str,
) -> Result<InviteUserResponse, Response> {
    let subject = normalize_required_subject(&body.subject, request_id)?;
    let email = normalize_optional_email(body.email.as_deref(), request_id)?;
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
    let ttl_policy =
        load_recovery_token_ttl_policy_in_transaction(&mut tx, context.environment_id, request_id)
            .await?;
    let expires_in_secs = local_credentials::sanitize_recovery_token_ttl(
        body.expires_in_seconds,
        RecoveryTokenPurpose::Activation,
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
    let (user_id, user) = insert_invited_user(
        &mut tx,
        context.environment_id,
        &subject,
        email.as_deref(),
        "A user with that subject already exists",
        request_id,
    )
    .await?;
    let (issued, redeem_url) = issue_recovery_token_with_redeem_url(
        &mut tx,
        &issuer_url,
        user_id,
        RecoveryTokenPurpose::Activation,
        expires_in_secs,
        context.session.administrator_id,
        request_id,
    )
    .await?;
    write_user_management_audit_event(
        &mut tx,
        context,
        request_id,
        EndUserAuditEvent {
            event_type: "management.user.invited.v1",
            target_id: user_id,
            data: serde_json::json!({
                "userId": &user.id,
                "subject": &user.subject,
                "email": &user.email,
                "status": &user.status,
                "activationTokenId": issued.id,
                "activationExpiresAt": issued.expires_at,
            }),
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    let activation = load_issued_recovery_token_response_required(
        &context.pool,
        user_id,
        issued,
        redeem_url,
        request_id,
    )
    .await?;

    Ok(InviteUserResponse { user, activation })
}
