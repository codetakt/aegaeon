#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationLogoutRecoveryIncidents",
    tag = "federation",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("connectionId" = Option<String>, Query, description = "Optional connection identifier (UUIDv4) filter"),
        ("status" = Option<String>, Query, description = "Optional incident status filter"),
        ("recoveryPolicy" = Option<String>, Query, description = "Optional recovery policy filter"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Federation logout recovery incidents", body = ListFederationLogoutRecoveryIncidentsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Environment not found", body = ErrorResponse)
    )
)]
pub(super) fn list_federation_logout_recovery_incidents() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationLogoutRecoveryIncidents/{incidentId}",
    tag = "federation",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("incidentId" = String, Path, description = "Incident identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Federation logout recovery incident", body = FederationLogoutRecoveryIncident),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn get_federation_logout_recovery_incident() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationLogoutRecoveryIncidents/{incidentId}/clear",
    tag = "federation",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("incidentId" = String, Path, description = "Incident identifier (UUIDv4)")
    ),
    request_body = ClearFederationLogoutRecoveryIncidentRequest,
    responses(
        (status = 204, description = "Incident cleared"),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Incident already resolved", body = ErrorResponse)
    )
)]
pub(super) fn clear_federation_logout_recovery_incident() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationTrustAnchors",
    tag = "federation",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Federation trust anchors list", body = ListFederationTrustAnchorsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Environment not found", body = ErrorResponse)
    )
)]
pub(super) fn list_federation_trust_anchors() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationTrustAnchors",
    tag = "federation",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = CreateFederationTrustAnchorRequest,
    responses(
        (status = 201, description = "Federation trust anchor created", body = FederationTrustAnchor),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Environment not found", body = ErrorResponse),
        (status = 409, description = "Trust anchor already exists", body = ErrorResponse)
    )
)]
pub(super) fn create_federation_trust_anchor() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationTrustAnchors/{trustAnchorId}",
    tag = "federation",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("trustAnchorId" = String, Path, description = "Trust anchor identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Federation trust anchor", body = FederationTrustAnchor),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Trust anchor not found", body = ErrorResponse)
    )
)]
pub(super) fn get_federation_trust_anchor() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationTrustAnchors/{trustAnchorId}",
    tag = "federation",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("trustAnchorId" = String, Path, description = "Trust anchor identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "Federation trust anchor deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Trust anchor not found", body = ErrorResponse)
    )
)]
pub(super) fn delete_federation_trust_anchor() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationEntityCache",
    tag = "federation",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Federation entity cache entries", body = ListFederationEntityCacheResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Environment not found", body = ErrorResponse)
    )
)]
pub(super) fn list_federation_entity_cache() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationEntityCache/{entityCacheId}/refresh",
    tag = "federation",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("entityCacheId" = String, Path, description = "Federation entity cache entry identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Federation entity cache entry refreshed", body = FederationEntityCacheEntry),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Federation entity cache entry not found", body = ErrorResponse),
        (status = 409, description = "Trust chain resolution failed", body = ErrorResponse),
        (status = 502, description = "Upstream federation metadata unavailable", body = ErrorResponse)
    )
)]
pub(super) fn refresh_federation_entity_cache_entry() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationEntityCache/{entityCacheId}",
    tag = "federation",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("entityCacheId" = String, Path, description = "Federation entity cache entry identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "Federation entity cache entry deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Federation entity cache entry not found", body = ErrorResponse)
    )
)]
pub(super) fn delete_federation_entity_cache_entry() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationTrustChains",
    tag = "federation",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Federation trust chains", body = ListFederationTrustChainsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Environment not found", body = ErrorResponse)
    )
)]
pub(super) fn list_federation_trust_chains() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationTrustChains/{trustChainId}/refresh",
    tag = "federation",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("trustChainId" = String, Path, description = "Federation trust chain identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Federation trust chain refreshed", body = FederationTrustChainEntry),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Federation trust chain not found", body = ErrorResponse),
        (status = 409, description = "Trust chain resolution failed", body = ErrorResponse),
        (status = 502, description = "Upstream federation metadata unavailable", body = ErrorResponse)
    )
)]
pub(super) fn refresh_federation_trust_chain() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/federationTrustChains/{trustChainId}",
    tag = "federation",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("trustChainId" = String, Path, description = "Federation trust chain identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "Federation trust chain deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Federation trust chain not found", body = ErrorResponse)
    )
)]
pub(super) fn delete_federation_trust_chain() {}
