use crate::web::management::federation_cache::{
    delete_federation_trust_chain_row, load_federation_trust_chain_entry,
};
use crate::web::management::{
    begin_management_transaction, commit_management_transaction, management_db_pool,
    require_federation_lifecycle_resource_scope, require_management_session_async,
    require_team_lifecycle_role_in_transaction, write_management_control_plane_audit_event,
    AppState, ManagementControlPlaneAuditEvent, RequestContext, TeamEnvironmentTrustChainPath,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};

pub(in crate::web::management::federation) async fn delete_federation_trust_chain(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<TeamEnvironmentTrustChainPath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let trust_chain_id = match params.trust_chain_id(&ctx.request_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let (scope, trust_chain_id) = match require_federation_lifecycle_resource_scope(
        pool,
        &params,
        trust_chain_id,
        &session,
        &ctx.request_id,
        "Insufficient permissions for federation trust chain operations",
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    let mut tx = match begin_management_transaction(pool, &ctx.request_id).await {
        Ok(tx) => tx,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        &session,
        &ctx.request_id,
        "Insufficient permissions for federation trust chain operations",
    )
    .await
    {
        return resp;
    }
    let existing = match load_federation_trust_chain_entry(
        &mut tx,
        trust_chain_id,
        scope.environment,
        &ctx.request_id,
    )
    .await
    {
        Ok(existing) => existing,
        Err(resp) => return resp,
    };
    if let Err(resp) = delete_federation_trust_chain_row(
        &mut tx,
        trust_chain_id,
        scope.environment,
        &ctx.request_id,
    )
    .await
    {
        return resp;
    }

    let audit_data = serde_json::json!({
        "trustChainId": existing.id,
        "leafEntityId": existing.leaf_entity_id,
        "anchorEntityId": existing.anchor_entity_id,
    });
    if let Err(resp) = write_management_control_plane_audit_event(
        &mut tx,
        ManagementControlPlaneAuditEvent {
            scope,
            administrator_id: session.administrator_id,
            request_id: &ctx.request_id,
            event_type: "management.federationTrustChain.deleted.v1",
            target_type: "FEDERATION_TRUST_CHAIN",
            target_id: existing.id.clone(),
            data: audit_data,
        },
    )
    .await
    {
        return resp;
    }

    if let Err(resp) = commit_management_transaction(tx, &ctx.request_id).await {
        return resp;
    }

    StatusCode::NO_CONTENT.into_response()
}
