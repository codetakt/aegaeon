use super::*;
pub(super) const BROWSER: &str = "__Host-aegaeon-invitation-browser";
pub(super) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        for part in header.to_str().ok()?.split(';') {
            let Some((key, value)) = part.trim().split_once('=') else {
                continue;
            };
            if key == name && (value.is_empty() || found.replace(value).is_some()) {
                return None;
            }
        }
    }
    found
}
pub(super) fn browser(store: &Store, headers: &HeaderMap) -> Option<String> {
    let value = cookie(headers, BROWSER)?;
    let (nonce, tag) = value.split_once('.')?;
    if nonce.len() != 36
        || Uuid::parse_str(nonce).is_err()
        || !equal(tag, &store.mac("browser", nonce))
    {
        return None;
    }
    Some(value.to_owned())
}
pub(super) fn new_browser(store: &Store) -> String {
    let id = Uuid::new_v4().to_string();
    format!("{}.{}", id, store.mac("browser", &id))
}
pub(super) fn session(id: Uuid) -> String {
    format!("__Host-aegaeon-invite-{id}")
}
pub(super) fn equal(left: &str, right: &str) -> bool {
    crate::util::constant_time_eq(left.as_bytes(), right.as_bytes())
}
/// Authenticate the common browser envelope before acquiring a store connection.
pub(super) fn post_credentials<'a>(
    store: &Store,
    issuer: &str,
    headers: &'a HeaderMap,
    query: Option<&str>,
) -> Result<(String, &'a str)> {
    let unique = |name: &str| {
        crate::organizations::http_input::one_header(headers, name).map_err(|_| Error::Invalid)
    };
    let origin = url::Url::parse(issuer)
        .map_err(|_| Error::Unavailable)?
        .origin()
        .ascii_serialization();
    if query.is_some() || unique("content-type")? != Some("application/json") {
        return Err(Error::Invalid);
    }
    if unique("origin")? != Some(origin.as_str()) {
        return Err(Error::Refused);
    }
    let browser = browser(store, headers).ok_or(Error::Refused)?;
    let csrf = unique("x-csrf-token")?.ok_or(Error::Refused)?;
    Ok((browser, csrf))
}
pub(super) fn set(r: &mut Response, name: &str, value: &str, max_age: i64) {
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{name}={value}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}"
    )) {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
}

/// Before fragment import the server only knows the anonymous browser. Issue
/// one nonce per landing. For a return visit also bind it to the GET's handle.
pub(super) fn landing_csrf(store: &Store, browser: &str, flow: Option<Uuid>, now: i64) -> String {
    let nonce = Uuid::new_v4();
    let payload = format!("{now}.{nonce}");
    let tag = store.mac(
        "mail-entry",
        &format!(
            "{browser}/{}/{payload}",
            flow.map(|v| v.to_string()).unwrap_or_default()
        ),
    );
    format!("{payload}.{tag}")
}
pub(super) fn valid_landing(
    store: &Store,
    browser: &str,
    flow: Option<Uuid>,
    value: &str,
    now: i64,
) -> bool {
    let Some((payload, tag)) = value.rsplit_once('.') else {
        return false;
    };
    let Some((timestamp, nonce)) = payload.split_once('.') else {
        return false;
    };
    if value.len() > 128
        || nonce.len() != 36
        || Uuid::parse_str(nonce).is_err()
        || timestamp
            .parse::<i64>()
            .ok()
            .is_none_or(|t| t > now || t <= now.saturating_sub(1800))
    {
        return false;
    }
    equal(
        tag,
        &store.mac(
            "mail-entry",
            &format!(
                "{browser}/{}/{payload}",
                flow.map(|v| v.to_string()).unwrap_or_default()
            ),
        ),
    )
}
