#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users",
    tag = "users",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token"),
        ("includeDeleted" = Option<bool>, Query, description = "Include deleted users in the result set")
    ),
    responses(
        (status = 200, description = "Users list", body = ListUsersResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_users() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = User),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Environment not found", body = ErrorResponse),
        (status = 409, description = "Conflict", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn create_user() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}",
    tag = "users",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "User", body = User, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn get_user() {}

#[utoipa::path(
    patch,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)"),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = User),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 409, description = "Conflict", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn update_user() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "User deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn delete_user() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/restore",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "User restored", body = User),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn restore_user() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/suspend",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "User suspended", body = User),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn suspend_user() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/unsuspend",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "User unsuspended", body = User),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn unsuspend_user() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/invalidateSessions",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "User sessions invalidated"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn invalidate_user_sessions() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/revokeRefreshTokens",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "User refresh tokens revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn revoke_user_refresh_tokens() {}
