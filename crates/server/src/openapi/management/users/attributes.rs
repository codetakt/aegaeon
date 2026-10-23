#![allow(dead_code)] // OpenAPI marker functions.
use crate::management::types::{
    ErrorResponse, LocalAttributesResponse, ReplaceLocalAttributesRequest,
    UserAttributeSourcesResponse,
};

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/attributes",
    tag = "users",
    params(("teamId" = String, Path), ("environmentId" = String, Path), ("userId" = String, Path)),
    responses(
        (status = 200, description = "Attribute sources and provenance", body = UserAttributeSourcesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Human OWNER or ADMINISTRATOR required", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Attribute source operation failed", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn get_user_attributes() {}

#[utoipa::path(
    put,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/attributes",
    tag = "users",
    params(("teamId" = String, Path), ("environmentId" = String, Path), ("userId" = String, Path), ("Origin" = String, Header), ("X-CSRF-Token" = String, Header)),
    request_body = ReplaceLocalAttributesRequest,
    responses(
        (status = 200, description = "Local namespace replaced atomically", body = LocalAttributesResponse),
        (status = 400, description = "Invalid attributes", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Role, Origin or CSRF check failed", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 409, description = "Stale baseRevision", body = ErrorResponse),
        (status = 422, description = "Malformed or unknown request fields"),
        (status = 500, description = "Attribute source operation failed", body = ErrorResponse),
        (status = 503, description = "Mandatory audit failed; replacement rolled back", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn replace_local_attributes() {}
