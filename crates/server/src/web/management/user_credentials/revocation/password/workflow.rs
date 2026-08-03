use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    load_managed_user_identity_for_update, management_internal_error,
    write_user_management_audit_event, EndUserAuditEvent, UserManagementContext,
};
use super::super::super::responses::load_user_credentials_response;
use crate::local_credentials;
use crate::management::types::UserCredentialsResponse;
use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

pub(super) async fn revoke_user_password_credential_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<UserCredentialsResponse, Response> {
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
    let revoked = local_credentials::revoke_password_credential(
        &mut tx,
        user_id,
        Some(context.session.administrator_id),
    )
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to revoke password credential"))?
    .ok_or_else(|| {
        error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Active password credential not found",
            None,
            Some(request_id),
        )
    })?;

    write_user_management_audit_event(
        &mut tx,
        context,
        request_id,
        EndUserAuditEvent {
            event_type: "management.user.passwordCredential.revoked.v1",
            target_id: user_id,
            data: serde_json::json!({
                "userId": user_id.to_string(),
                "subject": &identity.subject,
                "email": &identity.email,
                "passwordCredential": {
                    "id": revoked.id,
                    "status": revoked.status,
                }
            }),
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    load_user_credentials_response(&context.pool, user_id, request_id).await
}
