#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.

use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/apiKeys",
    tag = "apiKeys",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token"),
        ("Authorization" = String, Header, description = "Optional Bearer management API key for non-browser automation")
    ),
    responses(
        (status = 200, description = "Active API keys for the team", body = ListApiKeysResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Team not found", body = ErrorResponse)
    )
)]
pub(super) fn list_api_keys() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/apiKeys",
    tag = "apiKeys",
    params(
        ("Origin" = String, Header, description = "Origin header for cookie-authenticated browser sessions"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)")
    ),
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key created; raw value is returned only once", body = CreateApiKeyResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Team not found", body = ErrorResponse)
    )
)]
pub(super) fn create_api_key() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/apiKeys/{apiKeyId}/revoke",
    tag = "apiKeys",
    params(
        ("Origin" = String, Header, description = "Origin header for cookie-authenticated browser sessions"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("apiKeyId" = String, Path, description = "API key identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "API key revoked"),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse)
    )
)]
pub(super) fn revoke_api_key() {}
