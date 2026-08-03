#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/grants",
    tag = "users",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "User consent grant inventory", body = ListUserGrantsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_user_grants() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/grants/{grantId}/revoke",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)"),
        ("grantId" = String, Path, description = "Opaque grant inventory identifier")
    ),
    responses(
        (status = 204, description = "Consent grant revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Grant not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn revoke_user_grant() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/refreshTokens",
    tag = "users",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "User refresh-token inventory", body = ListUserRefreshTokensResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_user_refresh_tokens() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/refreshTokens/{refreshTokenId}/revoke",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)"),
        ("refreshTokenId" = String, Path, description = "Opaque refresh-token inventory identifier")
    ),
    responses(
        (status = 204, description = "Refresh token revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Refresh token not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn revoke_user_refresh_token_inventory() {}
