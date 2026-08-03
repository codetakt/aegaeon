#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/connections",
    tag = "connections",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("configurationVersionId" = Option<String>, Query, description = "Configuration version identifier (UUIDv4). Defaults to active configuration."),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Connections list", body = ListConnectionsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_connections() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/connections",
    tag = "connections",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("configurationVersionId" = Option<String>, Query, description = "Configuration version identifier (UUIDv4). Defaults to active configuration.")
    ),
    request_body = CreateConnectionRequest,
    responses(
        (status = 201, description = "Connection created", body = ConnectionMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (duplicate connection identifier)", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn create_connection() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/connections/{connectionId}",
    tag = "connections",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("connectionId" = String, Path, description = "Connection identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Connection", body = Connection, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn get_connection() {}

#[utoipa::path(
    patch,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/connections/{connectionId}",
    tag = "connections",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("connectionId" = String, Path, description = "Connection identifier (UUIDv4)"),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = UpdateConnectionRequest,
    responses(
        (status = 200, description = "Connection updated", body = ConnectionMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn update_connection() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/connections/{connectionId}",
    tag = "connections",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("connectionId" = String, Path, description = "Connection identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "Connection deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn delete_connection() {}
