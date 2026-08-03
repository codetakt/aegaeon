use super::super::super::{
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
};
use super::super::context::ClientAuditContext;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn write_client_assignment_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ClientAuditContext<'_>,
    event_type: &str,
    oauth_profile_id: Uuid,
    client_identifier: &str,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "oauthProfileId": oauth_profile_id.to_string(),
        "configurationVersionId": audit_context.configuration_version_id.to_string(),
        "profileType": "DOWNSTREAM",
        "assigneeType": "CLIENT",
        "assigneeId": audit_context.client_id.to_string(),
        "clientIdentifier": client_identifier,
    });

    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope: audit_context.environment.scope,
            administrator_id: audit_context.administrator_id,
            request_id: audit_context.request_id,
            event_type,
            target_type: "OAUTH_PROFILE",
            target_id: oauth_profile_id.to_string(),
            data: audit_data,
        },
    )
    .await
}
