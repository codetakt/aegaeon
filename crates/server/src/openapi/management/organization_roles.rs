#![allow(dead_code)] // Utoipa marker functions.
use crate::openapi::types::ErrorResponse;
use crate::organizations::{
    http_input::role_policy::ReplaceRolePolicyRequest,
    operators::mutations::role_policy::RolePolicy,
};

#[utoipa::path(
    get, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/role-policy", tag = "organizations",
    description = "Read the retained role vocabulary under current configure authority; keys are semantic names, not object IDs.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid")),
    responses((status = 200, description = "Current representation or authorized replay; no-store", body = RolePolicy, headers(("ETag" = String, description = "Strong role-policy representation validator"))), (status = 400, description = "Malformed vocabulary or precondition", body = ErrorResponse), (status = 401, description = "Invalid or expired human session", body = ErrorResponse), (status = 403, description = "Current capability, scope or last-manager protection refused", body = ErrorResponse), (status = 409, description = "Conflict or retained capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale precondition", body = ErrorResponse), (status = 413, description = "Body too large", body = ErrorResponse), (status = 428, description = "Exact If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn read_role_policy() {}

#[utoipa::path(
    put, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/role-policy", tag = "organizations",
    description = "Replace the complete retained role vocabulary, preserve existing keys, version changed meanings and retain current managers.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("Origin" = String, Header, description = "Configured console origin"), ("Idempotency-Key" = String, Header, description = "Exact retained command key"), ("If-Match" = String, Header, description = "Strong role-policy UUID and revision validator")),
    request_body = ReplaceRolePolicyRequest,
    responses((status = 200, description = "Current representation or authorized replay; no-store", body = RolePolicy, headers(("ETag" = String, description = "Strong role-policy representation validator"))), (status = 400, description = "Malformed vocabulary or precondition", body = ErrorResponse), (status = 401, description = "Invalid or expired human session", body = ErrorResponse), (status = 403, description = "Current capability, scope or last-manager protection refused", body = ErrorResponse), (status = 409, description = "Conflict or retained capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale precondition", body = ErrorResponse), (status = 413, description = "Body too large", body = ErrorResponse), (status = 428, description = "Exact If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn replace_role_policy() {}
