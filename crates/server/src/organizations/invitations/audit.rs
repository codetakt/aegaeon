//! Executor provenance for actions whose initiating principal is a different actor.
//! Legacy actor/client columns retain the initiating invitation principal.
use super::*;

pub(super) fn executor(
    stored: &Stored,
    request_id: &str,
    reason: &str,
    basis: &serde_json::Value,
) -> Result<AuditActor, AuthorityError> {
    let mut actor = stored.authority.actor.with_basis(serde_json::json!({
        "kind":"invitation_derived","invitationId":stored.invitation.id,
        "invitationRevision":stored.invitation.revision,"originatingPrincipal":{
            "id":stored.authority.actor.id,"kind":stored.authority.actor.kind,
            "clientId":stored.authority.actor.client_id,
            "clientRegistrationId":stored.authority.actor.client_registration_id,
            "requestId":stored.authority.actor.request_id,
            "basis":stored.authority.actor.basis},
        "executor":basis
    }));
    actor.request_id = request_id.into();
    actor.reason = reason.into();
    actor.validate()?;
    Ok(actor)
}

pub(super) fn delivery(
    stored: &Stored,
    object: Uuid,
    revision: i64,
    at: i64,
) -> Result<AuditActor, AuthorityError> {
    executor(
        stored,
        &format!("delivery:{object}:{revision}"),
        "organization delivery attempt",
        &serde_json::json!({"kind":"service","service":"organization_delivery","objectId":object,"deliveryRevision":revision,"claimedAt":at}),
    )
}
