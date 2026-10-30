use super::*;
use crate::organizations::http_input::invitations::{
    AcceptInvitationRequest, RecipientChallengeRequest,
};

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

#[utoipa::path(post, path = "/organization-invitations/{domain}/{invitation}/challenges", tag = "Organizations",
    description = "Recipient-only profile. A fresh proof of the retained recipient address is required separately from the authenticated user. Queues the challenge for configured delivery; never returns a capability/address. Exact application/json <=64 KiB, no query. No GET/HEAD acceptance. Retry the same body and key with a fresh DPoP proof.",
    params(("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid"), ("Idempotency-Key" = String, Header, min_length = 1, max_length = 128)),
    request_body = RecipientChallengeRequest,
    security(("recipientDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Challenge queued or current matching receipt; no-store", body = ChallengeResponse), (status = 400, description = "Malformed or mismatched request", body = ResourceError), (status = 401, description = "Invalid credential or DPoP challenge", body = ResourceError), (status = 403, description = "Current authority refused", body = ResourceError), (status = 409, description = "Receipt conflict or exhausted limit", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn challenge() {}

#[utoipa::path(post, path = "/organization-invitations/{domain}/{invitation}/accept", tag = "Organizations",
    description = "Explicit first-administrator or delegated member acceptance. Requires both invitation and current recipient challenge capabilities, exact authenticated root/client/user/key, original inviter and current role versions. One atomic membership/audit effect; first-admin acceptance also activates the provisioning organization; current authenticated replay is idempotent. Does not expand existing OAuth organization grants. Exact application/json <=64 KiB, no query.",
    params(("domain" = String, Path, format = "uuid"), ("invitation" = String, Path, format = "uuid")),
    request_body = AcceptInvitationRequest,
    security(("recipientDpopToken" = [], "resourceDpopProof" = [])),
    responses((status = 200, description = "Accepted membership or current retained result; no-store", body = AcceptanceResponse), (status = 400, description = "Malformed or mismatched request", body = ResourceError), (status = 401, description = "Invalid credential or DPoP challenge", body = ResourceError), (status = 403, description = "Current authority refused", body = ResourceError), (status = 409, description = "Conflicting state or exhausted limit", body = ResourceError), (status = 503, description = "Authority unavailable", body = ResourceError)))]
pub(super) fn accept() {}
