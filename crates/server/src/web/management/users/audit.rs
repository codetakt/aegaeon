use super::super::{write_user_management_audit_event, EndUserAuditEvent, UserManagementContext};
use crate::management::types::User;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

fn user_change_audit_data(previous: &User, current: &User) -> serde_json::Value {
    serde_json::json!({
        "userId": &current.id,
        "previous": {
            "subject": &previous.subject,
            "email": &previous.email,
            "status": &previous.status,
        },
        "current": {
            "subject": &current.subject,
            "email": &current.email,
            "status": &current.status,
        },
    })
}

pub(super) async fn write_user_change_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    context: &UserManagementContext,
    request_id: &str,
    event_type: &'static str,
    user_id: Uuid,
    previous: &User,
    current: &User,
) -> Result<(), Response> {
    write_user_management_audit_event(
        tx,
        context,
        request_id,
        EndUserAuditEvent {
            event_type,
            target_id: user_id,
            data: user_change_audit_data(previous, current),
        },
    )
    .await
}
