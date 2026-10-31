use crate::organizations::witness::creation::{Input, Kind};
use crate::web::management::{error_response, UserManagementContext};
use aegaeon_crypto::hash::sha256_digest;
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use uuid::Uuid;

fn invalid(request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "A canonical Idempotency-Key UUID and bounded creation fields are required",
        None,
        Some(request_id),
    )
}

#[derive(Clone, Copy)]
pub(in crate::web::management) enum Profile {
    Create,
    Invite(Option<i64>),
}

pub(in crate::web::management) fn input(
    context: &UserManagementContext,
    headers: &HeaderMap,
    subject: &str,
    email: Option<&str>,
    profile: Profile,
    request_id: &str,
) -> Result<Input, Response> {
    let mut values = headers.get_all("idempotency-key").iter();
    let raw = values
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| invalid(request_id))?;
    if values.next().is_some() || raw.len() != 36 {
        return Err(invalid(request_id));
    }
    let key = Uuid::parse_str(raw).map_err(|_| invalid(request_id))?;
    if key.is_nil()
        || key.to_string() != raw
        || subject.len() > 255
        || email.is_some_and(|v| v.len() > 1_048_576)
    {
        return Err(invalid(request_id));
    }
    let (kind, tag, domain, expiry) = match profile {
        Profile::Create => (
            Kind::ManagementCreate,
            1,
            "aegaeon-creation-management-create-v1",
            None,
        ),
        Profile::Invite(ttl) => {
            // Validate invariant credential bounds before retaining an owner. The
            // current Environment policy is still locked and checked in apply().
            if crate::local_credentials::sanitize_recovery_token_ttl(
                ttl,
                crate::local_credentials::RecoveryTokenPurpose::Activation,
                crate::local_credentials::RecoveryTokenTtlPolicy::baseline(),
            )
            .is_err()
            {
                return Err(invalid(request_id));
            }
            (
                Kind::ManagementInvite,
                2,
                "aegaeon-creation-management-invite-v1",
                Some(ttl),
            )
        }
    };
    let mut selector = b"aegaeon-creation-management-selector-v1\0".to_vec();
    selector.extend(context.environment_id.as_bytes());
    selector.push(tag);
    selector.extend(key.as_bytes());
    let mut actor = b"aegaeon-creation-management-actor-v1\0".to_vec();
    for id in [
        context.team_id,
        context.tenant_id,
        context.environment_id,
        context.session.administrator_id,
    ] {
        actor.extend(id.as_bytes());
    }
    let mut payload = domain.as_bytes().to_vec();
    payload.push(0);
    payload.extend((subject.len() as u32).to_be_bytes());
    payload.extend(subject.as_bytes());
    match email {
        Some(value) => {
            payload.push(1);
            payload.extend((value.len() as u32).to_be_bytes());
            payload.extend(value.as_bytes());
        }
        None => payload.push(0),
    }
    if let Some(ttl) = expiry {
        match ttl {
            Some(value) => {
                payload.push(1);
                payload.extend((value as u64).to_be_bytes());
            }
            None => payload.push(0),
        }
    }
    Input::new(
        kind,
        sha256_digest(&selector),
        sha256_digest(&actor),
        sha256_digest(&payload),
        Some(subject),
    )
    .map_err(|_| invalid(request_id))
}
