#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients",
    tag = "clients",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Clients list", body = ListClientsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_clients() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients",
    tag = "clients",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = CreateClientRequest,
    responses(
        (status = 201, description = "Client created", body = ClientMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(super) fn create_client() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}",
    tag = "clients",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("clientId" = String, Path, description = "Client identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Client", body = Client, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn get_client() {}

#[utoipa::path(
    patch,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}",
    tag = "clients",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("clientId" = String, Path, description = "Client identifier (UUIDv4)"),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = UpdateClientRequest,
    responses(
        (status = 200, description = "Client updated", body = ClientMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(super) fn update_client() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}",
    tag = "clients",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("clientId" = String, Path, description = "Client identifier (UUIDv4)")
    ),
    request_body = ConfigurationTransactionRequest,
    responses(
        (status = 200, description = "Client deleted", body = EnvironmentMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(super) fn delete_client() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets",
    tag = "clientSecrets",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("clientId" = String, Path, description = "Client identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (default 50, max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Client secrets list", body = ListClientSecretsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_client_secrets() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets",
    tag = "clientSecrets",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("clientId" = String, Path, description = "Client identifier (UUIDv4)")
    ),
    request_body = IssueClientSecretRequest,
    responses(
        (status = 201, description = "Client secret issued", body = IssueClientSecretResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(super) fn issue_client_secret() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets/{clientSecretId}/revoke",
    tag = "clientSecrets",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("clientId" = String, Path, description = "Client identifier (UUIDv4)"),
        ("clientSecretId" = String, Path, description = "Client secret identifier (UUIDv4)")
    ),
    request_body = ConfigurationTransactionRequest,
    responses(
        (status = 200, description = "Client secret revoked", body = ClientSecretMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(super) fn revoke_client_secret() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets/revokeAll",
    tag = "clientSecrets",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("clientId" = String, Path, description = "Client identifier (UUIDv4)")
    ),
    request_body = ConfigurationTransactionRequest,
    responses(
        (status = 200, description = "All client secrets revoked", body = EnvironmentMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(super) fn revoke_all_client_secrets() {}
