use axum::http::{header, HeaderMap, HeaderValue};

use aegaeon_crypto::hash::sha256_hex;

pub(super) fn cookie_name(state: &str) -> String {
    format!("__Host-aegaeon-upstream-{}", sha256_hex(state.as_bytes()))
}

pub(super) fn cookie_value(state: &str, secret: &str, max_age: u64) -> String {
    format!(
        "{}={secret}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax",
        cookie_name(state)
    )
}

/// Select exactly one well-formed cookie, including across separate Cookie headers.
pub(super) fn browser_digest(headers: &HeaderMap, state: &str) -> Option<String> {
    let name = cookie_name(state);
    let mut selected = None;
    for header in headers.get_all(header::COOKIE) {
        for pair in header.to_str().ok()?.split(';') {
            let pair = pair.trim();
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key.trim() != name {
                continue;
            }
            if selected.is_some()
                || key != name
                || value.len() != 43
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            {
                return None;
            }
            selected = Some(sha256_hex(value.as_bytes()));
        }
    }
    selected
}

pub(super) fn clear_cookie(headers: &mut HeaderMap, state: &str) {
    if let Ok(value) = HeaderValue::from_str(&cookie_value(state, "", 0)) {
        headers.append(header::SET_COOKIE, value);
    }
}
