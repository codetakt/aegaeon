#![allow(dead_code)] // Utoipa marker functions.
use crate::openapi::types::ErrorResponse;
use crate::organizations::http_input::{
    objects::{CreateOrganizationRequest, OrganizationListResponse, OrganizationResponse},
    ConfigurationReason,
};

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations", operation_id = "organization_domain_post_by_domain_organizations", tag = "organizations",
    description = "Create a provisioning organization with an exact external ID; current provision authority, no implicit membership.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("Origin" = String, Header, description = "Configured console origin"), ("Idempotency-Key" = String, Header, description = "Exact retained command key")),
    request_body = CreateOrganizationRequest,
    responses((status = 200, description = "Current representation or authorized replay; no-store", body = OrganizationResponse, headers(("ETag" = String, description = "Strong exact object validator"))), (status = 400, description = "Malformed input", body = ErrorResponse), (status = 401, description = "Invalid or expired human session", body = ErrorResponse), (status = 403, description = "Current capability or scope refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Conflict or retained capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale precondition", body = ErrorResponse), (status = 413, description = "Body too large", body = ErrorResponse), (status = 428, description = "Exact If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn create_organization() {}

#[utoipa::path(
    get, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations/{organization}", operation_id = "organization_domain_get_by_domain_organizations_by_organization", tag = "organizations",
    description = "Read one retained scoped organization; requires current reconcile authority.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("organization" = String, Path, format = "uuid")),
    responses((status = 200, description = "Current representation or authorized replay; no-store", body = OrganizationResponse, headers(("ETag" = String, description = "Strong exact object validator"))), (status = 400, description = "Malformed input", body = ErrorResponse), (status = 401, description = "Invalid or expired human session", body = ErrorResponse), (status = 403, description = "Current capability or scope refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Conflict or retained capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale precondition", body = ErrorResponse), (status = 413, description = "Body too large", body = ErrorResponse), (status = 428, description = "Exact If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn read_organization() {}

#[utoipa::path(
    get, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations", operation_id = "organization_domain_get_by_domain_organizations", tag = "organizations",
    description = "Bounded current-authority reconciliation, including tombstones; cursor is not authorization.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("pageSize" = Option<String>, Query, description = "Canonical 1-100, default 50"), ("pageToken" = Option<String>, Query, description = "Bounded collection and scope cursor")),
    responses((status = 200, description = "Current representation or authorized replay; no-store", body = OrganizationListResponse), (status = 400, description = "Malformed input", body = ErrorResponse), (status = 401, description = "Invalid or expired human session", body = ErrorResponse), (status = 403, description = "Current capability or scope refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Conflict or retained capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale precondition", body = ErrorResponse), (status = 413, description = "Body too large", body = ErrorResponse), (status = 428, description = "Exact If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn list_organizations() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations/{organization}/suspend", operation_id = "organization_domain_post_by_domain_organizations_by_organization_suspend", tag = "organizations",
    description = "Suspend an active organization through restrictive admission; requires provision and exact ETag.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("organization" = String, Path, format = "uuid"), ("Origin" = String, Header, description = "Configured console origin"), ("Idempotency-Key" = String, Header, description = "Exact retained command key"), ("If-Match" = String, Header, description = "Strong exact object UUID and revision")),
    request_body = ConfigurationReason,
    responses((status = 200, description = "Current representation or authorized replay; no-store", body = OrganizationResponse, headers(("ETag" = String, description = "Strong exact object validator"))), (status = 400, description = "Malformed input", body = ErrorResponse), (status = 401, description = "Invalid or expired human session", body = ErrorResponse), (status = 403, description = "Current capability or scope refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Conflict or retained capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale precondition", body = ErrorResponse), (status = 413, description = "Body too large", body = ErrorResponse), (status = 428, description = "Exact If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn suspend_organization() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations/{organization}/delete", operation_id = "organization_domain_post_by_domain_organizations_by_organization_delete", tag = "organizations",
    description = "Irreversibly tombstone a retained organization through restrictive admission; external ID stays reserved.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("organization" = String, Path, format = "uuid"), ("Origin" = String, Header, description = "Configured console origin"), ("Idempotency-Key" = String, Header, description = "Exact retained command key"), ("If-Match" = String, Header, description = "Strong exact object UUID and revision")),
    request_body = ConfigurationReason,
    responses((status = 200, description = "Current representation or authorized replay; no-store", body = OrganizationResponse, headers(("ETag" = String, description = "Strong exact object validator"))), (status = 400, description = "Malformed input", body = ErrorResponse), (status = 401, description = "Invalid or expired human session", body = ErrorResponse), (status = 403, description = "Current capability or scope refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Conflict or retained capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale precondition", body = ErrorResponse), (status = 413, description = "Body too large", body = ErrorResponse), (status = 428, description = "Exact If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn delete_organization() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations/{organization}/administrator-recovery", operation_id = "organization_domain_post_by_domain_organizations_by_organization_administrator_recovery", tag = "organizations",
    description = "Begin recovery only with no effective administrator; current human Team owner, explicit provision authority, reason and exact ETag. Advances generation and closes business access until a new administrator accepts.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("organization" = String, Path, format = "uuid"), ("Origin" = String, Header, description = "Configured console origin"), ("Idempotency-Key" = String, Header, description = "Exact retained command key"), ("If-Match" = String, Header, description = "Strong exact object UUID and revision")),
    request_body = ConfigurationReason,
    responses((status = 200, description = "Current representation or authorized replay; no-store", body = OrganizationResponse, headers(("ETag" = String, description = "Strong exact object validator"))), (status = 400, description = "Malformed input", body = ErrorResponse), (status = 401, description = "Invalid or expired human session", body = ErrorResponse), (status = 403, description = "Current capability or scope refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Conflict or retained capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale precondition", body = ErrorResponse), (status = 413, description = "Body too large", body = ErrorResponse), (status = 428, description = "Exact If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn prepare_administrator_recovery() {}
