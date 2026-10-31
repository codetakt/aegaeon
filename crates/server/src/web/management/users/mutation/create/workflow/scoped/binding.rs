use super::*;
use aegaeon_crypto::hash::sha256_digest;
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

pub(super) fn input(
    context: &UserManagementContext,
    headers: &HeaderMap,
    subject: &str,
    email: Option<&str>,
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
    let mut selector = b"aegaeon-creation-management-selector-v1\0".to_vec();
    selector.extend(context.environment_id.as_bytes());
    selector.push(1);
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
    let mut payload = b"aegaeon-creation-management-create-v1\0".to_vec();
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
    Input::new(
        Kind::ManagementCreate,
        sha256_digest(&selector),
        sha256_digest(&actor),
        sha256_digest(&payload),
        Some(subject),
    )
    .map_err(|_| invalid(request_id))
}
