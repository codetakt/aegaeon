use super::*;
use crate::organizations::http_input::invitations::{
    AcceptInvitationRequest, RecipientChallengeRequest,
};
use crate::organizations::invitations::{AllocatedChallenge, ChallengeStatus};

#[derive(ToSchema)]
#[schema(rename_all = "camelCase")]
pub(super) struct ChallengeResponse {
    #[schema(format = "uuid")]
    challenge_id: String,
}

#[derive(ToSchema)]
#[schema(rename_all = "camelCase")]
pub(super) struct AcceptanceResponse {
    #[schema(format = "uuid")]
    organization_id: String,
    #[schema(format = "uuid")]
    user_id: String,
    #[schema(format = "uuid")]
    incarnation: String,
    revision: i64,
}

#[utoipa::path(post, path = "/organization-invitations/{domain}/{invitation}/challenge-status", tag = "Organizations",
    description = "Read the remaining allocations and exclusive invitation expiry for an eligible recipient with a live invitation proof. No reservation, allocation or delivery.",
    params(("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid")),
    request_body = RecipientChallengeRequest,
    security(("recipientDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Current shared budget and invitation expiry, no-store", body = ChallengeStatus), (status = 400, description = "Malformed request", body = ResourceError), (status = 401, description = "Invalid credential or DPoP proof", body = ResourceError), (status = 403, description = "Current recipient or invitation refused", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn challenge_status() {}

#[utoipa::path(post, path = "/organization-invitations/{domain}/{invitation}/challenges", tag = "Organizations",
    description = "Recipient-only profile. A fresh proof of the retained recipient address is required separately from the authenticated user. Queues the challenge for configured delivery; never returns a capability/address. Exact application/json <=64 KiB, no query. No GET/HEAD acceptance. Retry the same body and key with a fresh DPoP proof.",
    params(("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid"), ("Idempotency-Key" = String, Header, min_length = 1, max_length = 128)),
    request_body = RecipientChallengeRequest,
    security(("recipientDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Challenge allocated or replayed. Extended JSON includes its original expiry and current shared budget.", headers(("Vary" = String, description = "Accept")), content((ChallengeResponse = "application/json"), (AllocatedChallenge = "application/vnd.aegaeon.invitation-challenge.v2+json"))), (status = 400, description = "Malformed or mismatched request", body = ResourceError), (status = 401, description = "Invalid credential or DPoP challenge", body = ResourceError), (status = 403, description = "Current authority refused", body = ResourceError), (status = 406, description = "Unsupported response representation", body = ResourceError), (status = 409, description = "Receipt conflict or exhausted limit", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn challenge() {}

#[utoipa::path(post, path = "/organization-invitations/{domain}/{invitation}/preview", tag = "Organizations",
    description = "Read verified invitation details before confirming a Pending invitation. Requires the invitation proof, recipient challenge proof and live recipient binding. Returns a strong validator for the displayed organization and offered roles. No membership or message is created.",
    params(("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid")),
    request_body = AcceptInvitationRequest,
    security(("recipientDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Verified details, no-store", body = crate::organizations::invitations::preview::Preview, headers(("ETag" = String, description = "Strong opaque confirmation validator"))), (status = 400, description = "Invalid request or proof", body = ResourceError), (status = 401, description = "Invalid credential or DPoP proof", body = ResourceError), (status = 403, description = "Current authority or eligibility refused", body = ResourceError), (status = 409, description = "Display metadata unavailable", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn preview() {}

#[utoipa::path(post, path = "/organization-invitations/{domain}/{invitation}/accept", tag = "Organizations",
    description = "Explicit first-administrator or delegated member acceptance. Requires both invitation and current recipient challenge capabilities, exact authenticated root/client/user/key, original inviter and current role versions. One atomic membership/audit effect; first-admin acceptance also activates the provisioning organization; current authenticated replay is idempotent. Does not expand existing OAuth organization grants. Exact application/json <=64 KiB, no query. A conditional acceptance retains the pre-accept tag with its result. Replay of that receipt requires the same tag.",
    params(("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid"), ("If-Match" = Option<String>, Header, description="One strong preview validator. Required for pinned hosted invitations and conditional receipt replay.")),
    request_body = AcceptInvitationRequest,
    security(("recipientDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Accepted membership or current retained result; no-store", body = AcceptanceResponse), (status = 400, description = "Malformed or mismatched request", body = ResourceError), (status = 401, description = "Invalid credential or DPoP challenge", body = ResourceError), (status = 403, description = "Current authority refused", body = ResourceError), (status = 409, description = "Display metadata unavailable, conflicting state or exhausted limit", body = ResourceError), (status = 412, description="Stale preview or mismatched receipt validator", body=ResourceError), (status=428,description="Required preview validator missing",body=ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn accept() {}
