use super::super::super::super::federation_cache::{
    delete_federation_trust_anchor_row, load_federation_trust_anchor_entry,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction,
    require_federation_lifecycle_scope, require_team_lifecycle_role_in_transaction,
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

const TRUST_ANCHOR_FORBIDDEN_MESSAGE: &str =
    "Insufficient permissions for federation trust anchor operations";

pub(super) async fn delete_federation_trust_anchor_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentTrustAnchorPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let scope = require_federation_lifecycle_scope(
        pool,
        params,
        session,
        request_id,
        TRUST_ANCHOR_FORBIDDEN_MESSAGE,
    )
    .await?;
    let trust_anchor_id = params.trust_anchor_id(request_id)?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        TRUST_ANCHOR_FORBIDDEN_MESSAGE,
    )
    .await?;
    let existing =
        load_federation_trust_anchor_entry(&mut tx, trust_anchor_id, scope.environment, request_id)
            .await?;
    delete_federation_trust_anchor_row(&mut tx, trust_anchor_id, scope.environment, request_id)
        .await?;

    let audit_data = serde_json::json!({
        "trustAnchorId": existing.id,
        "entityId": existing.entity_id,
        "hasMetadataPolicy": existing.metadata_policy.is_some(),
    });
    write_management_control_plane_audit_event(
        &mut tx,
        ManagementControlPlaneAuditEvent {
            scope,
            administrator_id: session.administrator_id,
            request_id,
            event_type: "management.federationTrustAnchor.deleted.v1",
            target_type: "FEDERATION_TRUST_ANCHOR",
            target_id: existing.id.clone(),
            data: audit_data,
        },
    )
    .await?;

    commit_management_transaction(tx, request_id).await
}
