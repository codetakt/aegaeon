use crate::federation::FederationError;
use crate::management::types::FederationTrustChainEntry;
use crate::web::management::federation_cache::{
    duration_secs_i64, load_federation_trust_chain_entry, load_resolvable_trust_anchors,
    resolve_refreshed_trust_chain_payload, store_refreshed_federation_trust_chain,
};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction,
    federation_management_error_response, require_federation_lifecycle_resource_scope,
    require_team_lifecycle_role_in_transaction, write_management_control_plane_audit_event,
    ManagementControlPlaneAuditEvent, TeamEnvironmentTrustChainPath,
};
use axum::response::Response;
use sqlx::PgPool;
use std::time::Duration;

pub(super) async fn refresh_federation_trust_chain_inner(
    pool: &PgPool,
    params: &TeamEnvironmentTrustChainPath,
    session: &ManagementSession,
    trust_chain_cache_ttl: Duration,
    outbound_allowed_domains: Vec<String>,
    request_id: &str,
) -> Result<FederationTrustChainEntry, Response> {
    let trust_chain_id = params.trust_chain_id(request_id)?;
    let (scope, trust_chain_id) = require_federation_lifecycle_resource_scope(
        pool,
        params,
        trust_chain_id,
        session,
        request_id,
        "Insufficient permissions for federation trust chain operations",
    )
    .await?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for federation trust chain operations",
    )
    .await?;
    let existing =
        load_federation_trust_chain_entry(&mut tx, trust_chain_id, scope.environment, request_id)
            .await?;

    let trust_anchors =
        load_resolvable_trust_anchors(&mut tx, scope.environment, request_id).await?;
    commit_management_transaction(tx, request_id).await?;

    if trust_anchors.is_empty() {
        return Err(federation_management_error_response(
            FederationError::ChainResolution(
                "no trust anchors configured for this environment".to_string(),
            ),
            request_id,
        ));
    }

    let chain_jwts = resolve_refreshed_trust_chain_payload(
        &existing,
        trust_anchors,
        outbound_allowed_domains,
        request_id,
    )
    .await?;

    let ttl_secs = duration_secs_i64(trust_chain_cache_ttl, request_id)?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for federation trust chain operations",
    )
    .await?;
    let refreshed = store_refreshed_federation_trust_chain(
        &mut tx,
        trust_chain_id,
        scope.environment,
        chain_jwts,
        ttl_secs,
        request_id,
    )
    .await?;

    let audit_data = serde_json::json!({
        "trustChainId": refreshed.id,
        "leafEntityId": refreshed.leaf_entity_id,
        "anchorEntityId": refreshed.anchor_entity_id,
        "expiresAt": refreshed.expires_at,
    });
    write_management_control_plane_audit_event(
        &mut tx,
        ManagementControlPlaneAuditEvent {
            scope,
            administrator_id: session.administrator_id,
            request_id,
            event_type: "management.federationTrustChain.refreshed.v1",
            target_type: "FEDERATION_TRUST_CHAIN",
            target_id: refreshed.id.clone(),
            data: audit_data,
        },
    )
    .await?;

    commit_management_transaction(tx, request_id).await?;

    Ok(refreshed)
}
