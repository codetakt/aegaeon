use super::super::{
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
    ManagementEnvironmentRecord,
};
use crate::management::types::ClientSecret;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn write_client_secret_issued_audit(
    tx: &mut Transaction<'_, Postgres>,
    environment: &ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &str,
    client_id: Uuid,
    client_secret: &ClientSecret,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "clientSecretId": &client_secret.id,
        "clientId": client_id.to_string(),
        "configurationVersionId": environment.active_configuration_version_id.to_string(),
        "expiresAt": &client_secret.expires_at,
    });

    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope: environment.scope,
            administrator_id,
            request_id,
            event_type: "management.clientSecret.issued.v1",
            target_type: "CLIENT_SECRET",
            target_id: client_secret.id.clone(),
            data: audit_data,
        },
    )
    .await
}

pub(super) async fn write_client_secret_revoked_audit(
    tx: &mut Transaction<'_, Postgres>,
    environment: &ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &str,
    client_id: Uuid,
    client_secret_id: Uuid,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "clientSecretId": client_secret_id.to_string(),
        "clientId": client_id.to_string(),
    });

    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope: environment.scope,
            administrator_id,
            request_id,
            event_type: "management.clientSecret.revoked.v1",
            target_type: "CLIENT_SECRET",
            target_id: client_secret_id.to_string(),
            data: audit_data,
        },
    )
    .await
}

pub(super) async fn write_all_client_secrets_revoked_audit(
    tx: &mut Transaction<'_, Postgres>,
    environment: &ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &str,
    client_id: Uuid,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "clientId": client_id.to_string(),
        "scope": "all_active",
    });

    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope: environment.scope,
            administrator_id,
            request_id,
            event_type: "management.clientSecret.revokedAll.v1",
            target_type: "CLIENT",
            target_id: client_id.to_string(),
            data: audit_data,
        },
    )
    .await
}
