use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use uuid::Uuid;

use super::super::pagination::invalid_page_token_response;
use super::iso8601::parse_iso8601_epoch_secs;
use axum::response::Response;

const MAX_AUDIT_CURSOR_TOKEN_BYTES: usize = 160;
const MAX_AUDIT_CURSOR_DECODED_BYTES: usize = 120;

pub(in crate::web::management) fn encode_audit_cursor(occurred_at: &str, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{occurred_at}|{id}"))
}

pub(in crate::web::management) fn decode_audit_cursor(token: &str) -> Option<(String, Uuid)> {
    if token.is_empty() || token.len() > MAX_AUDIT_CURSOR_TOKEN_BYTES {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    if decoded.len() > MAX_AUDIT_CURSOR_DECODED_BYTES {
        return None;
    }
    let s = String::from_utf8(decoded).ok()?;
    let (ts, id_str) = s.split_once('|')?;
    parse_iso8601_epoch_secs(ts)?;
    let id = Uuid::parse_str(id_str).ok()?;
    Some((ts.to_string(), id))
}

pub(in crate::web::management) fn audit_cursor_from_page_token(
    page_token: Option<&str>,
    request_id: &str,
) -> Result<Option<(String, Uuid)>, Response> {
    page_token
        .map(|token| {
            decode_audit_cursor(token).ok_or_else(|| invalid_page_token_response(request_id))
        })
        .transpose()
}
