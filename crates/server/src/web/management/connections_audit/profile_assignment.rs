use super::super::parse_optional_stored_uuid;
use super::context::ConnectionAuditContext;
use super::events::write_connection_assignment_audit;
use crate::management::types::Connection;
use axum::response::Response;
use sqlx::{Postgres, Transaction};

pub(in crate::web::management) async fn write_connection_profile_assignment_delta_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ConnectionAuditContext<'_>,
    previous_connection: &Connection,
    current_connection: &Connection,
) -> Result<(), Response> {
    let previous_profile_id = parse_optional_stored_uuid(
        previous_connection.oauth_profile_id.as_deref(),
        "connection oauthProfileId",
        audit_context.request_id,
    )?;
    let current_profile_id = parse_optional_stored_uuid(
        current_connection.oauth_profile_id.as_deref(),
        "connection oauthProfileId",
        audit_context.request_id,
    )?;

    if previous_profile_id == current_profile_id {
        return Ok(());
    }

    if let Some(previous_profile_id) = previous_profile_id {
        write_connection_assignment_audit(
            tx,
            audit_context,
            "management.oauthProfile.unassigned.v1",
            previous_profile_id,
            &previous_connection.connection_identifier,
        )
        .await?;
    }
    if let Some(current_profile_id) = current_profile_id {
        write_connection_assignment_audit(
            tx,
            audit_context,
            "management.oauthProfile.assigned.v1",
            current_profile_id,
            &current_connection.connection_identifier,
        )
        .await?;
    }

    Ok(())
}
