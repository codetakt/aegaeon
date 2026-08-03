use super::super::super::super::super::UserManagementContext;
use super::executor::{transition_user_status, UserStatusTransition};
use crate::management::types::User;
use axum::response::Response;
use uuid::Uuid;

pub(in crate::web::management::users::mutation::status) async fn delete_user_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    transition_user_status(
        context,
        user_id,
        request_id,
        UserStatusTransition {
            required_status_filter: "AND u.status <> 'DELETED'",
            update_clause:
                "status = 'DELETED', blocked_at = NULL, blocked_reason = NULL, updated_at = now()",
            not_found_message: "User not found",
            failure_message: "Database query failed",
            audit_event_type: "management.user.deleted.v1",
        },
    )
    .await
    .map(|_| ())
}

pub(in crate::web::management::users::mutation::status) async fn restore_user_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<User, Response> {
    transition_user_status(
        context,
        user_id,
        request_id,
        UserStatusTransition {
            required_status_filter: "AND u.status = 'DELETED'",
            update_clause: r"status = CASE
    WHEN EXISTS (
      SELECT 1
      FROM aegaeon.end_user_password_credentials pc
      WHERE pc.end_user_id = u.id
        AND pc.status = 'ACTIVE'
    ) THEN 'ACTIVE'::aegaeon.end_user_status
    ELSE 'INVITED'::aegaeon.end_user_status
  END,
  blocked_at = NULL,
  blocked_reason = NULL,
  updated_at = now()",
            not_found_message: "User not found or not deleted",
            failure_message: "Database query failed",
            audit_event_type: "management.user.restored.v1",
        },
    )
    .await
}

pub(in crate::web::management::users::mutation::status) async fn suspend_user_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<User, Response> {
    transition_user_status(
        context,
        user_id,
        request_id,
        UserStatusTransition {
            required_status_filter: "AND u.status = 'ACTIVE'",
            update_clause: "status = 'SUSPENDED', blocked_at = now(), updated_at = now()",
            not_found_message: "User not found or already suspended",
            failure_message: "Failed to suspend user",
            audit_event_type: "management.user.suspended.v1",
        },
    )
    .await
}

pub(in crate::web::management::users::mutation::status) async fn unsuspend_user_inner(
    context: &UserManagementContext,
    user_id: Uuid,
    request_id: &str,
) -> Result<User, Response> {
    transition_user_status(
        context,
        user_id,
        request_id,
        UserStatusTransition {
            required_status_filter: "AND u.status = 'SUSPENDED'",
            update_clause:
                "status = 'ACTIVE', blocked_at = NULL, blocked_reason = NULL, updated_at = now()",
            not_found_message: "User not found or not suspended",
            failure_message: "Failed to unsuspend user",
            audit_event_type: "management.user.reactivated.v1",
        },
    )
    .await
}
