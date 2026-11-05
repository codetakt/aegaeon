use super::*;
use crate::organizations::{
    http_input::{invitations::IssueInvitationRequest, ConfigurationReason},
    invitations::Invitation,
};

#[utoipa::path(post, path = "/organizations/{organization}/invitations", tag = "Organizations",
    description = "Queue a delegated member invitation under current assignable roles and the original root ceiling. No capability or recipient in response. Default 24 hours, capped by original root expiry. Requires organization.members.manage, the dedicated selected-token audience, fresh DPoP and exact organization. No query; strict JSON up to 64 KiB for POST.",
    params(("organization" = String, Path, format = "uuid"), ("If-Match" = String, Header, description = "Specific organization ETag for issuance; invitation ETag for cancellation"), ("Idempotency-Key" = String, Header, min_length = 1, max_length = 128)),
    request_body = IssueInvitationRequest,
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current result; no-store", body = Invitation, headers(("ETag" = String, description = "Strong object/revision validator"))), (status = 400, description = "Malformed request", body = ResourceError), (status = 401, description = "Invalid token or DPoP proof", body = ResourceError), (status = 403, description = "Current authority refused", body = ResourceError), (status = 409, description = "Conflict or finite capacity exhausted", body = ResourceError), (status = 412, description = "Stale precondition", body = ResourceError), (status = 428, description = "Specific If-Match required", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn issue() {}

#[utoipa::path(get, path = "/organizations/{organization}/invitations/{invitation}", tag = "Organizations",
    description = "Read secret-free invitation metadata under current delegated management authority over retained roles. Requires organization.members.manage, the dedicated selected-token audience, fresh DPoP and exact organization. No query; strict JSON up to 64 KiB for POST.",
    params(("organization" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid")),
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current result; no-store", body = Invitation, headers(("ETag" = String, description = "Strong object/revision validator"))), (status = 400, description = "Malformed request", body = ResourceError), (status = 401, description = "Invalid token or DPoP proof", body = ResourceError), (status = 403, description = "Current authority refused", body = ResourceError), (status = 409, description = "Conflict or finite capacity exhausted", body = ResourceError), (status = 412, description = "Stale precondition", body = ResourceError), (status = 428, description = "Specific If-Match required", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn read() {}

#[utoipa::path(head, path = "/organizations/{organization}/invitations/{invitation}", tag = "Organizations",
    description = "Same current authority and ETag as GET; no response body. Requires organization.members.manage, the dedicated selected-token audience, fresh DPoP and exact organization. No query; strict JSON up to 64 KiB for POST.",
    params(("organization" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid")),
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current result; no-store", headers(("ETag" = String, description = "Strong object/revision validator"))), (status = 400, description = "Malformed request"), (status = 401, description = "Invalid token or DPoP proof"), (status = 403, description = "Current authority refused"), (status = 409, description = "Conflict or finite capacity exhausted"), (status = 412, description = "Stale precondition"), (status = 428, description = "Specific If-Match required"), (status = 503, description = "Authority unavailable")))]
pub(super) fn head() {}

#[utoipa::path(post, path = "/organizations/{organization}/invitations/{invitation}/revoke", tag = "Organizations",
    description = "Terminal cancellation under current management authority, including after the original inviter root expires. Separate reserved cancellation admission. Requires organization.members.manage, the dedicated selected-token audience, fresh DPoP and exact organization. No query; strict JSON up to 64 KiB for POST.",
    params(("organization" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid"), ("If-Match" = String, Header, description = "Specific organization ETag for issuance; invitation ETag for cancellation"), ("Idempotency-Key" = String, Header, min_length = 1, max_length = 128)),
    request_body = ConfigurationReason,
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current result; no-store", body = Invitation, headers(("ETag" = String, description = "Strong object/revision validator"))), (status = 400, description = "Malformed request", body = ResourceError), (status = 401, description = "Invalid token or DPoP proof", body = ResourceError), (status = 403, description = "Current authority refused", body = ResourceError), (status = 409, description = "Conflict or finite capacity exhausted", body = ResourceError), (status = 412, description = "Stale precondition", body = ResourceError), (status = 428, description = "Specific If-Match required", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn revoke() {}
