#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys",
    tag = "runtimeKeys",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Runtime keys list", body = ListRuntimeKeysResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_runtime_keys() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys",
    tag = "runtimeKeys",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = CreateRuntimeKeyRequest,
    responses(
        (status = 201, description = "Runtime key created", body = RuntimeKeyMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(super) fn create_runtime_key() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys/activateNext",
    tag = "runtimeKeys",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = ActivateRuntimeKeyRequest,
    responses(
        (status = 200, description = "Next runtime key activated for the requested usage", body = RuntimeKeyMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(super) fn activate_next_runtime_key() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys/{runtimeKeyId}/revoke",
    tag = "runtimeKeys",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("runtimeKeyId" = String, Path, description = "Runtime key identifier (UUIDv4)")
    ),
    request_body = ConfigurationTransactionRequest,
    responses(
        (status = 200, description = "Runtime key revoked", body = RuntimeKeyMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(super) fn revoke_runtime_key() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/keyStores/current",
    tag = "keyStores",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Current keystore configuration (redacted)", body = KeyStorePublicView, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn get_current_key_store() {}

#[utoipa::path(
    put,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/keyStores/current",
    tag = "keyStores",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = UpdateKeyStoreRequest,
    responses(
        (status = 200, description = "Keystore configuration updated", body = KeyStoreUpdateResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch or downgrade gate)", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(super) fn put_current_key_store() {}
