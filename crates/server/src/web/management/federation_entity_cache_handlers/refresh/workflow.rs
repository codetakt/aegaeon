use crate::federation::{verify_entity_configuration, HttpFederationFetcher};
use crate::management::types::FederationEntityCacheEntry;
use crate::web::management::federation_cache::{
    duration_secs_i64, load_federation_entity_cache_entry,
    store_refreshed_federation_entity_cache_entry,
};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction,
    federation_management_error_response, require_federation_lifecycle_resource_scope,
    require_team_lifecycle_role_in_transaction, serialize_management_json,
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
    TeamEnvironmentEntityCachePath,
};
use axum::response::Response;
use sqlx::PgPool;
use std::time::Duration;

async fn fetch_entity_configuration_jws(
    entity_id: String,
    outbound_allowed_domains: Vec<String>,
    request_id: &str,
) -> Result<String, Response> {
    let fetcher =
        HttpFederationFetcher::try_with_optional_allowed_domains(&outbound_allowed_domains)
            .map_err(|error| federation_management_error_response(error, request_id))?;
    fetcher
        .fetch_entity_configuration_jws(&entity_id)
        .await
        .map_err(|error| federation_management_error_response(error, request_id))
}

pub(super) async fn refresh_federation_entity_cache_entry_inner(
    pool: &PgPool,
    params: &TeamEnvironmentEntityCachePath,
    session: &ManagementSession,
    entity_cache_ttl: Duration,
    outbound_allowed_domains: Vec<String>,
    request_id: &str,
) -> Result<FederationEntityCacheEntry, Response> {
    let entity_cache_id = params.entity_cache_id(request_id)?;
    let (scope, entity_cache_id) = require_federation_lifecycle_resource_scope(
        pool,
        params,
        entity_cache_id,
        session,
        request_id,
        "Insufficient permissions for federation entity cache operations",
    )
    .await?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for federation entity cache operations",
    )
    .await?;
    let existing =
        load_federation_entity_cache_entry(&mut tx, entity_cache_id, scope.environment, request_id)
            .await?;
    commit_management_transaction(tx, request_id).await?;

    let jws = fetch_entity_configuration_jws(
        existing.entity_id.clone(),
        outbound_allowed_domains,
        request_id,
    )
    .await?;
    let statement = verify_entity_configuration(&jws)
        .map_err(|error| federation_management_error_response(error, request_id))?;
    let parsed_statement = serialize_management_json(
        &statement,
        request_id,
        "Failed to serialize federation entity statement",
    )?;

    let ttl_secs = duration_secs_i64(entity_cache_ttl, request_id)?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for federation entity cache operations",
    )
    .await?;
    let refreshed = store_refreshed_federation_entity_cache_entry(
        &mut tx,
        entity_cache_id,
        scope.environment,
        &jws,
        parsed_statement,
        ttl_secs,
        request_id,
    )
    .await?;

    let audit_data = serde_json::json!({
        "entityCacheId": refreshed.id,
        "entityId": refreshed.entity_id,
        "expiresAt": refreshed.expires_at,
    });
    write_management_control_plane_audit_event(
        &mut tx,
        ManagementControlPlaneAuditEvent {
            scope,
            administrator_id: session.administrator_id,
            request_id,
            event_type: "management.federationEntityCacheEntry.refreshed.v1",
            target_type: "FEDERATION_ENTITY_CACHE_ENTRY",
            target_id: refreshed.id.clone(),
            data: audit_data,
        },
    )
    .await?;

    commit_management_transaction(tx, request_id).await?;

    Ok(refreshed)
}
