use super::*;
use crate::organizations::http_input::ConfigurationReason;

#[derive(serde::Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ActivationRequest {
    #[schema(format = "uuid")]
    organization_id: String,
    audience: String,
    #[schema(min_items = 1, max_items = 64)]
    roles: Vec<String>,
    #[schema(min_length = 1, max_length = 1024)]
    reason: String,
}
#[derive(serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct AdministrativeGrantResponse {
    #[schema(format = "uuid")]
    id: String,
    #[schema(format = "uuid")]
    organization_id: String,
    audience: String,
    roles: Vec<String>,
    privileges: Vec<String>,
    revision: i64,
    /// Persisted lifecycle: active, expired or revoked; current policy may also deny access.
    state: String,
    issued_at: i64,
    expires_at: i64,
}

#[utoipa::path(post,path="/organization-support/{domain}/grants",tag="Organizations",
    description="Activate temporary support within the separate original approval and current operator entitlement. Requires explicit provider MFA policy and original auth_time less than 300 seconds old; grant expires no later than that absolute boundary or the parent/root. No membership is created. Strict JSON <=64 KiB, no query, idempotency and atomic audit. Permanent receipts: at most 16 per original root and 10000 per domain.",
    params(("domain"=String,Path,format="uuid"),("If-Match"=String,Header,description="Exact target organization ETag"),("Idempotency-Key"=String,Header,min_length=1,max_length=128)),
    request_body=ActivationRequest,security(("supportDpopToken"=[],"resourceDpopProof"=[])),
    responses((status=200,description="Activated grant or current exact replay; no-store",body=AdministrativeGrantResponse,headers(("ETag"=String,description="Grant UUID/revision validator"))),(status=400,description="Malformed request"),(status=401,description="Invalid original token or DPoP"),(status=403,description="Current or original authority refused"),(status=409,description="Changed replay or exhausted capacity"),(status=412,description="Stale organization"),(status=428,description="Specific If-Match required"),(status=503,description="Authority unavailable")))]
pub(super) fn activate() {}

#[utoipa::path(get,path="/organization-support/{domain}/grants/{grant}",tag="Organizations",
    description="Read a grant owned by the same original root, subject, client registration and DPoP key. No query or body. Policy disable does not prevent inspection under a still-valid parent credential. State describes persisted lifecycle; it does not confer current access.",
    params(("domain"=String,Path,format="uuid"),("grant"=String,Path,format="uuid")),security(("supportDpopToken"=[],"resourceDpopProof"=[])),
    responses((status=200,description="Owned grant; no-store",body=AdministrativeGrantResponse,headers(("ETag"=String,description="Grant UUID/revision validator"))),(status=400,description="Malformed request"),(status=401,description="Invalid parent token or DPoP"),(status=403,description="Ownership refused"),(status=503,description="Authority unavailable")))]
pub(super) fn read() {}

#[utoipa::path(head,path="/organization-support/{domain}/grants/{grant}",tag="Organizations",
    description="Same ownership, current identity and parent credential checks as GET, with no response body.",
    params(("domain"=String,Path,format="uuid"),("grant"=String,Path,format="uuid")),security(("supportDpopToken"=[],"resourceDpopProof"=[])),
    responses((status=200,description="Owned grant; no-store",headers(("ETag"=String,description="Grant UUID/revision validator"))),(status=400,description="Malformed request"),(status=401,description="Invalid parent token or DPoP"),(status=403,description="Ownership refused"),(status=503,description="Authority unavailable")))]
pub(super) fn head() {}

#[utoipa::path(post,path="/organization-support/{domain}/grants/{grant}/revoke",tag="Organizations",
    description="Terminal revocation by the original root owner; disabled support policy/domain does not prevent revocation while the parent credential and identity remain valid. Uses reserved cancellation admission. Strict JSON <=64 KiB, no query. Exact retry remains idempotent; never revives a grant.",
    params(("domain"=String,Path,format="uuid"),("grant"=String,Path,format="uuid"),("If-Match"=String,Header,description="Exact grant ETag"),("Idempotency-Key"=String,Header,min_length=1,max_length=128)),
    request_body=ConfigurationReason,security(("supportDpopToken"=[],"resourceDpopProof"=[])),
    responses((status=200,description="Revoked grant or exact replay; no-store",body=AdministrativeGrantResponse,headers(("ETag"=String,description="Grant UUID/revision validator"))),(status=400,description="Malformed request"),(status=401,description="Invalid parent token or DPoP"),(status=403,description="Ownership refused"),(status=409,description="Changed replay"),(status=412,description="Stale grant"),(status=428,description="Specific If-Match required"),(status=503,description="Authority unavailable")))]
pub(super) fn revoke() {}
