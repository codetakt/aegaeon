use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, insert_invited_user,
    normalize_optional_email, normalize_required_subject, write_user_management_audit_event,
    EndUserAuditEvent, UserManagementContext,
};
use crate::management::types::{CreateUserRequest, User};
use axum::response::Response;

pub(super) async fn create_user_inner(
    context: &UserManagementContext,
    body: &CreateUserRequest,
    request_id: &str,
) -> Result<User, Response> {
    let subject = normalize_required_subject(&body.subject, request_id)?;
    let email = normalize_optional_email(body.email.as_deref(), request_id)?;
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    context
        .require_lifecycle_role_in_transaction(&mut tx, request_id)
        .await?;
    let (user_id, user) = insert_invited_user(
        &mut tx,
        context.environment_id,
        &subject,
        email.as_deref(),
        "A user with that subject already exists",
        request_id,
    )
    .await?;

    write_user_management_audit_event(
        &mut tx,
        context,
        request_id,
        EndUserAuditEvent {
            event_type: "management.user.created.v1",
            target_id: user_id,
            data: serde_json::json!({
                "userId": &user.id,
                "subject": &user.subject,
                "email": &user.email,
                "status": &user.status,
            }),
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(user)
}
