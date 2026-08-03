#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/policies",
    tag = "policies",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Policies", body = PolicyDocument, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn get_policies() {}

#[utoipa::path(
    patch,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/policies",
    tag = "policies",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = PolicyPatchRequest,
    responses(
        (status = 200, description = "Policies updated in the management database; response reports whether the running server reloaded the policy", body = PolicyPatchResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch, `SECURITY_LEDGER_CONFLICT`, or downgrade gate)", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn patch_policies() {}
