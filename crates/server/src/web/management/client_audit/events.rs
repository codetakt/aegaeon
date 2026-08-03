mod assignment;
mod snapshot;

use super::super::{
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
    ManagementEnvironmentScope,
};
use super::basic::write_client_basic_audit_event;
use super::context::ClientAuditContext;
use crate::management::types::Client;
pub(in crate::web::management) use assignment::write_client_assignment_audit;
use axum::response::Response;
use snapshot::client_audit_snapshot;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn write_client_created_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ClientAuditContext<'_>,
    client: &Client,
) -> Result<(), Response> {
    write_client_basic_audit_event(
        tx,
        audit_context.environment.scope,
        audit_context.administrator_id,
        audit_context.request_id,
        "management.client.created.v1",
        audit_context.client_id.to_string(),
        serde_json::json!({
            "clientIdentifier": &client.client_identifier,
            "name": &client.name,
            "clientType": &client.client_type,
        }),
    )
    .await
}

pub(in crate::web::management) async fn write_client_deleted_audit(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    administrator_id: Uuid,
    request_id: &str,
    client_id: Uuid,
    client_identifier: &str,
) -> Result<(), Response> {
    write_client_basic_audit_event(
        tx,
        scope,
        administrator_id,
        request_id,
        "management.client.deleted.v1",
        client_id.to_string(),
        serde_json::json!({
            "clientIdentifier": client_identifier,
        }),
    )
    .await
}

pub(in crate::web::management) async fn write_client_updated_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ClientAuditContext<'_>,
    existing_client: &Client,
    client: &Client,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "clientId": audit_context.client_id.to_string(),
        "configurationVersionId": audit_context.configuration_version_id.to_string(),
        "previous": client_audit_snapshot(existing_client),
        "current": client_audit_snapshot(client),
    });

    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope: audit_context.environment.scope,
            administrator_id: audit_context.administrator_id,
            request_id: audit_context.request_id,
            event_type: "management.client.updated.v1",
            target_type: "CLIENT",
            target_id: audit_context.client_id.to_string(),
            data: audit_data,
        },
    )
    .await
}
