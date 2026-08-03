use super::super::parse_optional_stored_uuid;
use super::context::ClientAuditContext;
use super::events::write_client_assignment_audit;
use crate::management::types::Client;
use axum::response::Response;
use sqlx::{Postgres, Transaction};

pub(in crate::web::management) async fn write_client_profile_assignment_delta_audit(
    tx: &mut Transaction<'_, Postgres>,
    audit_context: ClientAuditContext<'_>,
    previous_client: &Client,
    current_client: &Client,
) -> Result<(), Response> {
    let previous_profile_id = parse_optional_stored_uuid(
        previous_client.oauth_profile_id.as_deref(),
        "client oauthProfileId",
        audit_context.request_id,
    )?;
    let current_profile_id = parse_optional_stored_uuid(
        current_client.oauth_profile_id.as_deref(),
        "client oauthProfileId",
        audit_context.request_id,
    )?;

    if previous_profile_id == current_profile_id {
        return Ok(());
    }

    if let Some(previous_profile_id) = previous_profile_id {
        write_client_assignment_audit(
            tx,
            audit_context,
            "management.oauthProfile.unassigned.v1",
            previous_profile_id,
            &previous_client.client_identifier,
        )
        .await?;
    }
    if let Some(current_profile_id) = current_profile_id {
        write_client_assignment_audit(
            tx,
            audit_context,
            "management.oauthProfile.assigned.v1",
            current_profile_id,
            &current_client.client_identifier,
        )
        .await?;
    }

    Ok(())
}
