#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/sessions",
    tag = "users",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "User session inventory", body = ListUserSessionsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_user_sessions() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/sessions/{sessionId}/revoke",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)"),
        ("sessionId" = String, Path, description = "Opaque session inventory identifier")
    ),
    responses(
        (status = 204, description = "User session revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn revoke_user_session() {}
