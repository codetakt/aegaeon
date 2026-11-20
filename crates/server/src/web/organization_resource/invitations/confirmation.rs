use super::*;
use axum::http::HeaderMap;

pub(super) enum Operation {
    Preview,
    Accept(Condition),
}

// Record syntax here; disclose precondition errors only after proof and authority checks.
pub(super) fn condition(headers: &HeaderMap) -> Condition {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(header) = values.next() else {
        return Condition::Missing;
    };
    if values.next().is_some() || header.as_bytes().len() > http_input::MAX_PRECONDITION_BYTES {
        return Condition::Invalid;
    }
    let mut value = header.as_bytes();
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    let Some(inner) = value
        .strip_prefix(b"\"")
        .and_then(|s| s.strip_suffix(b"\""))
    else {
        return Condition::Invalid;
    };
    if inner
        .iter()
        .all(|b| matches!(b,0x21|0x23..=0x7e|0x80..=0xff))
    {
        Condition::Tag(value.to_vec())
    } else {
        Condition::Invalid
    }
}

pub(super) struct ResponseFields {
    pub body: serde_json::Value,
    pub tag: Option<HeaderValue>,
    pub expires_at: i64,
}

pub(super) async fn run(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &service::Acceptance<'_>,
    runtime: &service::delegated::Runtime<'_>,
    operation: Operation,
) -> Result<ResponseFields, Response> {
    let refusal = |e: preview::Error| match e {
        preview::Error::Storage(e) => members::storage_error(state, &e),
        preview::Error::MissingTag => {
            error(state, StatusCode::PRECONDITION_REQUIRED, "invalid_request")
        }
        preview::Error::InvalidTag => invalid(state),
    };
    match operation {
        Operation::Preview => {
            let (view, tag, expires_at) = preview::preview(tx, input, runtime)
                .await
                .map_err(refusal)?;
            Ok(ResponseFields {
                body: serde_json::json!(view),
                tag: Some(HeaderValue::from_str(&tag).map_err(|_| unavailable(state))?),
                expires_at,
            })
        }
        Operation::Accept(condition) => {
            let (member, expires_at) =
                service::accept_conditional(tx, input, Some(runtime), &condition)
                    .await
                    .map_err(refusal)?;
            Ok(ResponseFields {
                body: serde_json::json!({"organizationId":member.organization_id,"userId":member.user_id,"incarnation":member.incarnation,"revision":member.revision}),
                tag: None,
                expires_at,
            })
        }
    }
}
