#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/oauthProfiles",
    tag = "oauthProfiles",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("configurationVersionId" = Option<String>, Query, description = "Configuration version identifier (UUIDv4). Defaults to active configuration."),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "OAuth profiles list", body = ListOAuthProfilesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_oauth_profiles() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/oauthProfiles",
    tag = "oauthProfiles",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("configurationVersionId" = Option<String>, Query, description = "Configuration version identifier (UUIDv4). Defaults to active configuration.")
    ),
    request_body = CreateOAuthProfileRequest,
    responses(
        (status = 201, description = "OAuth profile created", body = OAuthProfileMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn create_oauth_profile() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/oauthProfiles/{oauthProfileId}",
    tag = "oauthProfiles",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("oauthProfileId" = String, Path, description = "OAuth profile identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "OAuth profile", body = OAuthProfile, headers(("ETag" = String, description = "Strong entity tag for optimistic concurrency"))),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn get_oauth_profile() {}

#[utoipa::path(
    patch,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/oauthProfiles/{oauthProfileId}",
    tag = "oauthProfiles",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("oauthProfileId" = String, Path, description = "OAuth profile identifier (UUIDv4)"),
        ("If-Match" = Option<String>, Header, description = "Optional current ETag")
    ),
    request_body = UpdateOAuthProfileRequest,
    responses(
        (status = 200, description = "OAuth profile updated", body = OAuthProfileMutationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 412, description = "ETag precondition failed", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn update_oauth_profile() {}

#[utoipa::path(
    delete,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/oauthProfiles/{oauthProfileId}",
    tag = "oauthProfiles",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("oauthProfileId" = String, Path, description = "OAuth profile identifier (UUIDv4)")
    ),
    responses(
        (status = 204, description = "OAuth profile deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn delete_oauth_profile() {}
