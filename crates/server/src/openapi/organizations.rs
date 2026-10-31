#![allow(dead_code)] // Utoipa path markers and schema DTOs describe wire representations.
#![allow(clippy::needless_for_each)] // Utoipa schema assembly.
use crate::organizations::http_input::members::{
    MemberListResponse, MemberResponse, UpdateMemberRequest,
};
use utoipa::openapi::{
    security::{ApiKey, ApiKeyValue, SecurityScheme},
    Components,
};
use utoipa::{Modify, OpenApi, ToSchema};

mod delegated_invitations;
mod identity;
mod invitations;
mod support;

struct SenderAuthentication;
impl Modify for SenderAuthentication {
    fn modify(&self, api: &mut utoipa::openapi::OpenApi) {
        let components = api.components.get_or_insert_with(Components::new);
        components.add_security_scheme("identityCsrfCookie",SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
            "__Host-aegaeon-organization-identity-csrf","Fresh single-use browser CSRF cookie; matching csrf_token form field and exact same-origin Origin are also mandatory. This cookie is not an OAuth or membership credential."))));
        for (scheme, header, description) in [
            ("selectedDpopToken", "Authorization", "Complete Authorization value: DPoP <selected access token>. Requires exact {issuer}/organizations audience, original authorization and current primary authority. Bearer, session cookies and management API keys cannot substitute."),
            ("supportDpopToken", "Authorization", "Original code-issued DPoP token for exact {issuer}/organization-support audience and exactly organization.support.activate plus offline_access scopes; at most 300 seconds. Original approval, explicit provider MFA semantics and current support entitlement are mandatory."),
            ("recipientDpopToken", "Authorization", "DPoP token for exact {issuer}/organization-invitations audience and organization.invitation.accept scope; at most 300 seconds; current original root, configured client and active user required."),
            ("resourceDpopProof", "DPoP", "Fresh resource-server proof bound to the token (ath), method, canonical URI and original key; verifier nonce and replay requirements apply."),
        ] {
            components.add_security_scheme(scheme, SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(header, description))));
        }
    }
}

#[derive(ToSchema)]
struct SelectedDetail {
    r#type: String,
    identifier: String,
    privileges: Vec<String>,
    access_basis: String,
    #[schema(format = "uuid")]
    admin_access_grant_id: Option<String>,
}
#[derive(serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct ContextOrganization {
    #[schema(format = "uuid")]
    id: String,
    external_id: String,
    revision: i64,
    /// Quoted parent organization validator for invitation issuance If-Match.
    version_tag: String,
}
#[derive(ToSchema)]
struct ContextResponse {
    organization: ContextOrganization,
    iss: String,
    sub: String,
    authorization_details: Vec<SelectedDetail>,
    exp: i64,
}
#[derive(ToSchema)]
struct ResourceError {
    error: String,
    iss: String,
}

#[utoipa::path(get, path = "/organizations/context", tag = "Organizations",
    description = "Requires organization.context.read. Query and body are refused; no-store response.",
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current selected context", body = ContextResponse), (status = 400, description = "Malformed request", body = ResourceError), (status = 401, description = "Invalid credential or DPoP challenge", body = ResourceError), (status = 403, description = "Missing authority", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
fn context() {}

#[utoipa::path(head, path = "/organizations/context", tag = "Organizations",
    description = "Same authentication and authorization as GET; no response body.",
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current selected context; no-store"), (status = 400, description = "Malformed request"), (status = 401, description = "Invalid credential or DPoP challenge"), (status = 403, description = "Missing authority"), (status = 503, description = "Authority unavailable")))]
fn context_head() {}

#[utoipa::path(get, path = "/organizations/{organization}/members", tag = "Organizations",
    description = "Requires organization.members.read. Canonical UUID path and bounded current-state pagination; no-store.",
    params(("organization" = String, Path, format = "uuid"), ("limit" = Option<u32>, Query, minimum = 1, maximum = 100), ("after" = Option<String>, Query, max_length = 512)),
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current members and scope-bound next cursor; at most 64 KiB", body = MemberListResponse), (status = 400, description = "Malformed request or cursor", body = ResourceError), (status = 401, description = "Invalid credential or DPoP challenge", body = ResourceError), (status = 403, description = "Missing authority or foreign organization", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
fn list() {}

#[utoipa::path(head, path = "/organizations/{organization}/members", tag = "Organizations",
    description = "Same authorization and query checks as GET; no response body.",
    params(("organization" = String, Path, format = "uuid"), ("limit" = Option<u32>, Query, minimum = 1, maximum = 100), ("after" = Option<String>, Query, max_length = 512)),
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current members; no-store"), (status = 400, description = "Malformed request or cursor"), (status = 401, description = "Invalid credential or DPoP challenge"), (status = 403, description = "Missing authority or foreign organization"), (status = 503, description = "Authority unavailable")))]
fn list_head() {}

#[utoipa::path(get, path = "/organizations/{organization}/members/{user}", tag = "Organizations",
    description = "Requires organization.members.read; plain UUID organization/user identity. No body or query; no-store.",
    params(("organization" = String, Path, format = "uuid"), ("user" = String, Path, format = "uuid")),
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current member", body = MemberResponse, headers(("ETag" = String, description = "Strong incarnation/revision validator"))), (status = 400, description = "Malformed request", body = ResourceError), (status = 401, description = "Invalid credential or DPoP challenge", body = ResourceError), (status = 403, description = "Inaccessible member or missing authority", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
fn member() {}

#[utoipa::path(head, path = "/organizations/{organization}/members/{user}", tag = "Organizations",
    description = "Same checks and ETag as GET; no response body.",
    params(("organization" = String, Path, format = "uuid"), ("user" = String, Path, format = "uuid")),
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current member; no-store", headers(("ETag" = String, description = "Strong incarnation/revision validator"))), (status = 400, description = "Malformed request"), (status = 401, description = "Invalid credential or DPoP challenge"), (status = 403, description = "Inaccessible member or missing authority"), (status = 503, description = "Authority unavailable")))]
fn member_head() {}

#[utoipa::path(put, path = "/organizations/{organization}/members/{user}", tag = "Organizations",
    description = "Requires organization.members.manage and current authority over old and new roles. Existing active/suspended memberships only; no invitation acceptance or removed-member revival. Body <=64 KiB, exact application/json; no query. Owned operation may finish after response loss; retry the same key/request or read current state. Audit, outbox and receipt are atomic.",
    params(("organization" = String, Path, format = "uuid"), ("user" = String, Path, format = "uuid"), ("If-Match" = String, Header, description = "Exact strong incarnation/revision ETag"), ("Idempotency-Key" = String, Header, min_length = 1, max_length = 128)),
    request_body = UpdateMemberRequest,
    security(("selectedDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Updated member or authorized original receipt; no-store", body = MemberResponse, headers(("ETag" = String, description = "Result incarnation/revision validator"))), (status = 400, description = "Malformed request", body = ResourceError), (status = 401, description = "Invalid credential or DPoP challenge", body = ResourceError), (status = 403, description = "Current authority or transition refused", body = ResourceError), (status = 409, description = "Changed receipt or exhausted capacity", body = ResourceError), (status = 412, description = "Stale representation", body = ResourceError), (status = 428, description = "Strong If-Match required", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
fn update() {}

#[derive(OpenApi)]
#[openapi(
    modifiers(&SenderAuthentication),
    info(title = "Aegaeon Organizations Resource", version = "v1", description = "Optional Aegaeon profile. Resource access requires explicit activation, registered own audience, DPoP, original approval and current primary authority. The separately described browser enrollment forms use invitation/address proofs and CSRF; they issue neither tokens nor memberships. Specification generation does not establish release readiness or standards conformance."),
    paths(support::activate, support::read, support::head, support::revoke, identity::form, identity::head, identity::submit, context, context_head, list, list_head, member, member_head, update, invitations::challenge, invitations::accept, delegated_invitations::issue, delegated_invitations::read, delegated_invitations::head, delegated_invitations::revoke),
    components(schemas(support::ActivationRequest,support::AdministrativeGrantResponse, identity::IdentityForm, crate::organizations::invitations::enrollment::Purpose, ContextResponse, ContextOrganization, SelectedDetail, ResourceError, MemberResponse, MemberListResponse, UpdateMemberRequest, crate::organizations::http_input::invitations::RecipientChallengeRequest, crate::organizations::http_input::invitations::AcceptInvitationRequest, invitations::ChallengeResponse, invitations::AcceptanceResponse, crate::organizations::invitations::Invitation, crate::organizations::http_input::invitations::IssueInvitationRequest, crate::organizations::http_input::ConfigurationReason)),
    tags((name = "Organizations", description = "Selected Organizations authority"))
)]
pub struct OrganizationsApiV1;
