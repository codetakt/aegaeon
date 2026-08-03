use super::super::{
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
    ManagementEnvironmentRecord,
};
use super::input::RuntimeKeyCreateInput;
use crate::management::types::RuntimeKey;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) fn runtime_key_create_audit_data(
    input: &RuntimeKeyCreateInput,
) -> serde_json::Value {
    serde_json::json!({
        "usage": input.usage.as_db_str(),
        "kid": &input.kid,
        "algorithm": &input.algorithm,
        "provider": &input.provider,
        "initialStatus": input.initial_status,
        "providerConfigurationRedacted": true,
        "comment": &input.comment,
    })
}

pub(in crate::web::management) fn runtime_key_lifecycle_audit_data(
    runtime_key: &RuntimeKey,
    operation: &'static str,
    comment: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "operation": operation,
        "usage": &runtime_key.usage,
        "kid": &runtime_key.kid,
        "algorithm": &runtime_key.algorithm,
        "provider": &runtime_key.provider,
        "status": &runtime_key.status,
        "comment": comment,
    })
}

pub(super) struct RuntimeKeyLifecycleAudit<'a> {
    pub(super) runtime_key: &'a RuntimeKey,
    pub(super) event_type: &'static str,
    pub(super) operation: &'static str,
    pub(super) comment: Option<String>,
}

pub(super) async fn write_runtime_key_created_audit(
    tx: &mut Transaction<'_, Postgres>,
    environment: &ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &str,
    runtime_key_id: Uuid,
    input: &RuntimeKeyCreateInput,
) -> Result<(), Response> {
    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope: environment.scope,
            administrator_id,
            request_id,
            event_type: "management.runtimeKey.created.v1",
            target_type: "RUNTIME_KEY",
            target_id: runtime_key_id.to_string(),
            data: runtime_key_create_audit_data(input),
        },
    )
    .await
}

pub(super) async fn write_runtime_key_lifecycle_audit(
    tx: &mut Transaction<'_, Postgres>,
    environment: &ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &str,
    audit: RuntimeKeyLifecycleAudit<'_>,
) -> Result<(), Response> {
    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope: environment.scope,
            administrator_id,
            request_id,
            event_type: audit.event_type,
            target_type: "RUNTIME_KEY",
            target_id: audit.runtime_key.id.clone(),
            data: runtime_key_lifecycle_audit_data(
                audit.runtime_key,
                audit.operation,
                audit.comment.as_deref(),
            ),
        },
    )
    .await
}
