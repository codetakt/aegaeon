#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/invitations",
    tag = "users",
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Required canonical nonnil UUID for selected Organizations work; binds the original actor and invitation payload"),
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, format = "uuid", description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, format = "uuid", description = "Environment identifier (UUIDv4)")
    ),
    request_body = InviteUserRequest,
    responses(
        (status = 200, description = "User invited", body = InviteUserResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Committed invitation user no longer exists", body = ErrorResponse),
        (status = 409, description = "Creation conflict or one-time activation result unavailable on committed replay", body = ErrorResponse),
        (status = 503, description = "Creation evidence or current authority unavailable", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn invite_user() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/importCsv",
    tag = "users",
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Required canonical nonnil UUID for selected Organizations work; binds the complete normalized batch, at most 100 users"),
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, format = "uuid", description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, format = "uuid", description = "Environment identifier (UUIDv4)")
    ),
    request_body = ImportUsersCsvRequest,
    responses(
        (status = 200, description = "CSV users imported", body = ImportUsersCsvResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Committed batch contains a deleted user", body = ErrorResponse),
        (status = 409, description = "Creation conflict or one-time activation result unavailable on committed replay", body = ErrorResponse),
        (status = 503, description = "Creation evidence or current authority unavailable", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn import_users_csv() {}
