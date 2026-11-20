#![allow(dead_code)] // Utoipa operation definitions.
use crate::openapi::types::ErrorResponse;
use crate::organizations::{
    http_input::display::{PatchRoleDisplay, SetOrganizationDisplayName},
    operators::mutations::display::{OrganizationDisplay, RoleDisplay},
};

#[utoipa::path(
    get, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations/{organization}/display", tag="organizations", operation_id="get_organization_display",
    description="Current human domain provision authority. Read display metadata and its ETag, including when unset.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("organization" = String, Path, format = "uuid")),
    responses((status=200, description="Current display representation or authorized replay", headers(("ETag" = String, description="Strong display representation validator")), body=OrganizationDisplay),
        (status=400, description="Malformed display command", body=ErrorResponse),
        (status=401, description="Human session required", body=ErrorResponse),
        (status=403, description="Scoped operator grant required", body=ErrorResponse),
        (status=503, description="Admission or authority unavailable", body=ErrorResponse))
)]
pub(super) fn get_organization_display() {}

#[utoipa::path(
    head, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations/{organization}/display", tag="organizations", operation_id="head_organization_display",
    description="Current human domain provision authority. Read display metadata and its ETag, including when unset.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("organization" = String, Path, format = "uuid")),
    responses((status=200, description="Current display representation or authorized replay", headers(("ETag" = String, description="Strong display representation validator"))),
        (status=400, description="Malformed display command", body=ErrorResponse),
        (status=401, description="Human session required", body=ErrorResponse),
        (status=403, description="Scoped operator grant required", body=ErrorResponse),
        (status=503, description="Admission or authority unavailable", body=ErrorResponse))
)]
pub(super) fn head_organization_display() {}

#[utoipa::path(
    put, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations/{organization}/display", tag="organizations", operation_id="put_organization_display",
    description="Current human domain provision authority. Update display metadata with independent revisions.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("organization" = String, Path, format = "uuid"), ("Origin" = String, Header, description="Configured console origin"), ("Idempotency-Key" = String, Header, description="Retained command key"), ("If-Match" = String, Header, description="One strong display resource ETag")),
    request_body=SetOrganizationDisplayName,
    responses((status=200, description="Current display representation or authorized replay", headers(("ETag" = String, description="Strong display representation validator")), body=OrganizationDisplay),
        (status=400, description="Malformed display command", body=ErrorResponse),
        (status=401, description="Human session required", body=ErrorResponse),
        (status=403, description="Scoped operator grant required", body=ErrorResponse),
        (status=409, description="Receipt conflict or ordinary capacity exhausted", body=ErrorResponse),
        (status=412, description="Stale display ETag", body=ErrorResponse),
        (status=413, description="Body too large", body=ErrorResponse),
        (status=428, description="Missing If-Match", body=ErrorResponse),
        (status=503, description="Admission or authority unavailable", body=ErrorResponse))
)]
pub(super) fn put_organization_display() {}

#[utoipa::path(
    get, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/role-policy/display", tag="organizations", operation_id="get_role_display",
    description="Current human domain configure authority. Read display metadata and its ETag, including when unset.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid")),
    responses((status=200, description="Current display representation or authorized replay", headers(("ETag" = String, description="Strong display representation validator")), body=RoleDisplay),
        (status=400, description="Malformed display command", body=ErrorResponse),
        (status=401, description="Human session required", body=ErrorResponse),
        (status=403, description="Scoped operator grant required", body=ErrorResponse),
        (status=503, description="Admission or authority unavailable", body=ErrorResponse))
)]
pub(super) fn get_role_display() {}

#[utoipa::path(
    head, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/role-policy/display", tag="organizations", operation_id="head_role_display",
    description="Current human domain configure authority. Read display metadata and its ETag, including when unset.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid")),
    responses((status=200, description="Current display representation or authorized replay", headers(("ETag" = String, description="Strong display representation validator"))),
        (status=400, description="Malformed display command", body=ErrorResponse),
        (status=401, description="Human session required", body=ErrorResponse),
        (status=403, description="Scoped operator grant required", body=ErrorResponse),
        (status=503, description="Admission or authority unavailable", body=ErrorResponse))
)]
pub(super) fn head_role_display() {}

#[utoipa::path(
    patch, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/role-policy/display", tag="organizations", operation_id="patch_role_display",
    description="Current human domain configure authority. Update display metadata with independent revisions.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("Origin" = String, Header, description="Configured console origin"), ("Idempotency-Key" = String, Header, description="Retained command key"), ("If-Match" = String, Header, description="One strong display resource ETag")),
    request_body=PatchRoleDisplay,
    responses((status=200, description="Current display representation or authorized replay", headers(("ETag" = String, description="Strong display representation validator")), body=RoleDisplay),
        (status=400, description="Malformed display command", body=ErrorResponse),
        (status=401, description="Human session required", body=ErrorResponse),
        (status=403, description="Scoped operator grant required", body=ErrorResponse),
        (status=409, description="Receipt conflict or ordinary capacity exhausted", body=ErrorResponse),
        (status=412, description="Stale display ETag", body=ErrorResponse),
        (status=413, description="Body too large", body=ErrorResponse),
        (status=428, description="Missing If-Match", body=ErrorResponse),
        (status=503, description="Admission or authority unavailable", body=ErrorResponse))
)]
pub(super) fn patch_role_display() {}
