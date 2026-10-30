#![allow(dead_code)] // Utoipa metadata markers.
use crate::openapi::types::ErrorResponse;
use crate::organizations::invitations::Invitation;

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/organizations/{organization}/invitations", tag = "organizations",
    description = "Issue a first-administrator invitation for an empty provisioning organization. Requires current provision capability; does not activate membership.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("organization" = String, Path, format = "uuid"), ("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "Exact scoped replay key, at most128 bytes"), ("If-Match" = String, Header, description = "Specific strong current organization ETag")),
    request_body = crate::organizations::http_input::invitations::IssueInvitationRequest,
    responses((status = 200, description = "Current result; no-store", body = Invitation, headers(("ETag" = String, description = "Strong current object version"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Current human session required", body = ErrorResponse), (status = 403, description = "Scope, CSRF or current capability refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Replay conflict or finite capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale object version", body = ErrorResponse), (status = 413, description = "Body exceeds64KiB", body = ErrorResponse), (status = 428, description = "Specific If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn issue() {}

#[utoipa::path(
    get, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/invitations/{invitation}", tag = "organizations",
    description = "Read secret-free invitation metadata and a strong ETag. Requires current reconcile capability. GET never accepts an invitation.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid")),
    responses((status = 200, description = "Current result; no-store", body = Invitation, headers(("ETag" = String, description = "Strong current object version"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Current human session required", body = ErrorResponse), (status = 403, description = "Scope, CSRF or current capability refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Replay conflict or finite capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale object version", body = ErrorResponse), (status = 413, description = "Body exceeds64KiB", body = ErrorResponse), (status = 428, description = "Specific If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn read() {}

#[utoipa::path(
    head, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/invitations/{invitation}", tag = "organizations",
    description = "Read invitation metadata headers without a body. Requires current reconcile capability. HEAD never accepts an invitation.",
    security(("managementSessionCookie" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid")),
    responses((status = 200, description = "Current result; no-store", headers(("ETag" = String, description = "Strong current object version"))), (status = 400, description = "Malformed or ambiguous input"), (status = 401, description = "Current human session required"), (status = 403, description = "Scope, CSRF or current capability refused"), (status = 408, description = "Body deadline exceeded"), (status = 409, description = "Replay conflict or finite capacity exhausted"), (status = 412, description = "Stale object version"), (status = 413, description = "Body exceeds64KiB"), (status = 428, description = "Specific If-Match required"), (status = 503, description = "Admission or store unavailable; no fallback"))
)]
pub(in crate::openapi::management) fn head() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/invitations/{invitation}/revoke", tag = "organizations",
    description = "Cancel a pending invitation using current provision capability and reserved cancellation admission. Revocation is terminal and preserves history.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("team" = String, Path, format = "uuid"), ("environment" = String, Path, format = "uuid"), ("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid"), ("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "Exact scoped replay key, at most128 bytes"), ("If-Match" = String, Header, description = "Specific strong current invitation ETag")),
    request_body = crate::organizations::http_input::ConfigurationReason,
    responses((status = 200, description = "Current result; no-store", body = Invitation, headers(("ETag" = String, description = "Strong current object version"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Current human session required", body = ErrorResponse), (status = 403, description = "Scope, CSRF or current capability refused", body = ErrorResponse), (status = 408, description = "Body deadline exceeded", body = ErrorResponse), (status = 409, description = "Replay conflict or finite capacity exhausted", body = ErrorResponse), (status = 412, description = "Stale object version", body = ErrorResponse), (status = 413, description = "Body exceeds64KiB", body = ErrorResponse), (status = 428, description = "Specific If-Match required", body = ErrorResponse), (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn revoke() {}
