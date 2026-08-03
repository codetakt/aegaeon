use super::super::super::super::{
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
    ManagementEnvironmentScope,
};
use crate::management::types::FederationTrustAnchor;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn write_trust_anchor_created_audit(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    administrator_id: Uuid,
    request_id: &str,
    trust_anchor: &FederationTrustAnchor,
    entity_id: &str,
    has_metadata_policy: bool,
) -> Result<(), Response> {
    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope,
            administrator_id,
            request_id,
            event_type: "management.federationTrustAnchor.created.v1",
            target_type: "FEDERATION_TRUST_ANCHOR",
            target_id: trust_anchor.id.clone(),
            data: serde_json::json!({
                "trustAnchorId": &trust_anchor.id,
                "entityId": entity_id,
                "hasMetadataPolicy": has_metadata_policy,
            }),
        },
    )
    .await
}
