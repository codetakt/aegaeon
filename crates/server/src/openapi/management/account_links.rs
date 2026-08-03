#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/accountLinks",
    tag = "accountLinks",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = CreateAccountLinkRequest,
    responses(
        (status = 201, description = "Account link created", body = AccountLinkSummary),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Environment, connection, or user not found", body = ErrorResponse),
        (status = 409, description = "Account link already exists", body = ErrorResponse)
    )
)]
pub(super) fn create_account_link() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/accountLinks/conflictPreview",
    tag = "accountLinks",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = PreviewAccountLinkConflictRequest,
    responses(
        (status = 200, description = "Account link conflict preview", body = AccountLinkConflictPreview),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Environment or connection not found", body = ErrorResponse)
    )
)]
pub(super) fn preview_account_link_conflict() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/accountLinks/resolveConflict",
    tag = "accountLinks",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = ResolveAccountLinkConflictRequest,
    responses(
        (status = 200, description = "Account link conflict resolved", body = AccountLinkSummary),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Environment, connection, user, or conflict not found", body = ErrorResponse),
        (status = 409, description = "Conflict belongs to another connection", body = ErrorResponse)
    )
)]
pub(super) fn resolve_account_link_conflict() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/accountLinks",
    tag = "accountLinks",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token"),
        ("upstreamIssuer" = Option<String>, Query, description = "Substring match for the upstream issuer"),
        ("upstreamSubject" = Option<String>, Query, description = "Exact match for the upstream subject"),
        ("endUserSubject" = Option<String>, Query, description = "Substring match for the linked local subject"),
        ("endUserEmail" = Option<String>, Query, description = "Substring match for the linked local email"),
        ("connectionIdentifier" = Option<String>, Query, description = "Substring match for the upstream connection identifier")
    ),
    responses(
        (status = 200, description = "Account links list", body = ListAccountLinksResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_account_links() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/accountLinks/{accountLinkId}",
    tag = "accountLinks",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("accountLinkId" = String, Path, description = "Account link identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "Account link deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn delete_account_link() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/accountLinks/bulkRelink",
    tag = "accountLinks",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = BulkRelinkAccountLinksRequest,
    responses(
        (status = 200, description = "Account links relinked", body = BulkRelinkAccountLinksResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Environment, account link, or user not found", body = ErrorResponse)
    )
)]
pub(super) fn bulk_relink_account_links() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/accountLinks/{accountLinkId}/relink",
    tag = "accountLinks",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("accountLinkId" = String, Path, description = "Account link identifier (UUIDv4)")
    ),
    request_body = RelinkAccountLinkRequest,
    responses(
        (status = 200, description = "Account link relinked", body = AccountLinkSummary),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn relink_account_link() {}
