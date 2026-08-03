#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams",
    tag = "teams",
    params(
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Teams list", body = ListTeamsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_teams() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams",
    tag = "teams",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)")
    ),
    request_body = CreateTeamRequest,
    responses(
        (status = 201, description = "Team created", body = Team),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse)
    )
)]
pub(super) fn create_team() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}",
    tag = "teams",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Team", body = Team, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn get_team() {}

#[utoipa::path(
    patch,
    path = "/api/v1/teams/{teamId}",
    tag = "teams",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = UpdateTeamRequest,
    responses(
        (status = 200, description = "Team updated", body = Team),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(super) fn update_team() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}",
    tag = "teams",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "Team deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn delete_team() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/tenants",
    tag = "tenants",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Tenants list", body = ListTenantsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_tenants() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/tenants",
    tag = "tenants",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)")
    ),
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created", body = Tenant),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse)
    )
)]
pub(super) fn create_tenant() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/tenants/{tenantId}",
    tag = "tenants",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("tenantId" = String, Path, description = "Tenant identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Tenant", body = Tenant, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn get_tenant() {}

#[utoipa::path(
    patch,
    path = "/api/v1/teams/{teamId}/tenants/{tenantId}",
    tag = "tenants",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("tenantId" = String, Path, description = "Tenant identifier (UUIDv4)"),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = UpdateTenantRequest,
    responses(
        (status = 200, description = "Tenant updated", body = Tenant),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(super) fn update_tenant() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/tenants/{tenantId}",
    tag = "tenants",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("tenantId" = String, Path, description = "Tenant identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "Tenant deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn delete_tenant() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/tenants/{tenantId}/environments",
    tag = "environments",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("tenantId" = String, Path, description = "Tenant identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Environments list", body = ListEnvironmentsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_environments() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/tenants/{tenantId}/environments",
    tag = "environments",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("tenantId" = String, Path, description = "Tenant identifier (UUIDv4)")
    ),
    request_body = CreateEnvironmentRequest,
    responses(
        (status = 201, description = "Environment created", body = Environment),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse)
    )
)]
pub(super) fn create_environment() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}",
    tag = "environments",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        (
            "environmentId" = String,
            Path,
            description = "Environment identifier (UUIDv4). Tenant is omitted from this path (IDs are globally unique); the server must still validate Team ownership."
        )
    ),
    responses(
        (status = 200, description = "Environment", body = Environment, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn get_environment() {}

#[utoipa::path(
    patch,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}",
    tag = "environments",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        (
            "environmentId" = String,
            Path,
            description = "Environment identifier (UUIDv4). Tenant is omitted from this path (IDs are globally unique); the server must still validate Team ownership."
        ),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = UpdateEnvironmentRequest,
    responses(
        (status = 200, description = "Environment updated", body = Environment),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(super) fn update_environment() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}",
    tag = "environments",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        (
            "environmentId" = String,
            Path,
            description = "Environment identifier (UUIDv4). Tenant is omitted from this path (IDs are globally unique); the server must still validate Team ownership."
        )
    ),
    responses(
        (status = 204, description = "Environment deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn delete_environment() {}
