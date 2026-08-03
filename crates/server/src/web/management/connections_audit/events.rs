use super::context::ConnectionAuditContext;
use super::snapshot::connection_audit_snapshot;
use super::writer::write_connection_audit_event;
use crate::management::types::Connection;
use crate::web::management::connections_support::ConnectionInput;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn write_connection_created_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ConnectionAuditContext<'_>,
    input: &ConnectionInput,
    oauth_profile_id: Option<Uuid>,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "connectionId": audit_context.connection_id.to_string(),
        "configurationVersionId": audit_context.configuration_version_id.to_string(),
        "connectionIdentifier": &input.connection_identifier,
        "name": &input.name,
        "connectionType": &input.connection_type,
        "issuerUrl": &input.issuer_url,
        "clientId": &input.client_id,
        "clientAuthMethod": &input.client_auth_method,
        "status": &input.status,
        "oauthProfileId": oauth_profile_id.as_ref().map(Uuid::to_string),
    });

    write_connection_audit_event(
        tx,
        audit_context,
        "management.connection.created.v1",
        "CONNECTION",
        audit_context.connection_id.to_string(),
        audit_data,
    )
    .await
}

pub(in crate::web::management) async fn write_connection_updated_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ConnectionAuditContext<'_>,
    existing_connection: &Connection,
    connection: &Connection,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "connectionId": audit_context.connection_id.to_string(),
        "configurationVersionId": audit_context.configuration_version_id.to_string(),
        "previous": connection_audit_snapshot(existing_connection),
        "current": connection_audit_snapshot(connection),
    });

    write_connection_audit_event(
        tx,
        audit_context,
        "management.connection.updated.v1",
        "CONNECTION",
        audit_context.connection_id.to_string(),
        audit_data,
    )
    .await
}

pub(in crate::web::management) async fn write_connection_assignment_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ConnectionAuditContext<'_>,
    event_type: &str,
    oauth_profile_id: Uuid,
    connection_identifier: &str,
) -> Result<(), Response> {
    let assignment_data = serde_json::json!({
        "oauthProfileId": oauth_profile_id.to_string(),
        "configurationVersionId": audit_context.configuration_version_id.to_string(),
        "profileType": "UPSTREAM",
        "assigneeType": "CONNECTION",
        "assigneeId": audit_context.connection_id.to_string(),
        "connectionIdentifier": connection_identifier,
    });

    write_connection_audit_event(
        tx,
        audit_context,
        event_type,
        "OAUTH_PROFILE",
        oauth_profile_id.to_string(),
        assignment_data,
    )
    .await
}

pub(in crate::web::management) async fn write_connection_deleted_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ConnectionAuditContext<'_>,
    connection: &Connection,
) -> Result<(), Response> {
    let audit_data = serde_json::json!({
        "connectionId": audit_context.connection_id.to_string(),
        "configurationVersionId": audit_context.configuration_version_id.to_string(),
        "current": connection_audit_snapshot(connection),
    });

    write_connection_audit_event(
        tx,
        audit_context,
        "management.connection.deleted.v1",
        "CONNECTION",
        audit_context.connection_id.to_string(),
        audit_data,
    )
    .await
}
