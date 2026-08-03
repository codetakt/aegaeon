#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions",
    tag = "configurationVersions",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token"),
        ("upstreamIssuer" = Option<String>, Query, description = "Substring filter for upstream issuer"),
        ("endUserSubject" = Option<String>, Query, description = "Substring filter for end-user subject"),
        ("endUserEmail" = Option<String>, Query, description = "Substring filter for end-user email"),
        ("connectionIdentifier" = Option<String>, Query, description = "Substring filter for connection identifier")
    ),
    responses(
        (status = 200, description = "Configuration versions list", body = ListConfigurationVersionsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_configuration_versions() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions",
    tag = "configurationVersions",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)")
    ),
    request_body = CreateConfigurationVersionRequest,
    responses(
        (status = 201, description = "Configuration version created", body = ConfigurationVersion),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 409, description = "Conflict (base version mismatch)", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn create_configuration_version() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}",
    tag = "configurationVersions",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("configurationVersionId" = String, Path, description = "Configuration version identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Configuration version", body = ConfigurationVersion),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn get_configuration_version() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}/activate",
    tag = "configurationVersions",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("configurationVersionId" = String, Path, description = "Configuration version identifier (UUIDv4)")
    ),
    request_body = ActivateConfigurationVersionRequest,
    responses(
        (status = 200, description = "Configuration version activated", body = EnvironmentMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Conflict (`SECURITY_LEDGER_CONFLICT` or downgrade gate)", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn activate_configuration_version() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}/archive",
    tag = "configurationVersions",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("configurationVersionId" = String, Path, description = "Configuration version identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "Configuration version archived"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn archive_configuration_version() {}
