use super::super::{CSRF_COOKIE_NAME, MGMT_SESSION_COOKIE_NAME};

pub(in crate::web::management) fn build_csrf_set_cookie(token: &str, secure: bool) -> String {
    let mut attrs = vec![
        format!("{CSRF_COOKIE_NAME}={token}"),
        "Path=/api/v1".to_string(),
        "SameSite=Lax".to_string(),
    ];
    if secure {
        attrs.push("Secure".to_string());
    }
    attrs.join("; ")
}

pub(in crate::web::management) fn build_session_set_cookie(
    sid: &str,
    secure: bool,
    ttl_secs: u64,
) -> String {
    let mut attrs = vec![
        format!("{MGMT_SESSION_COOKIE_NAME}={sid}"),
        "Path=/api/v1".to_string(),
        "HttpOnly".to_string(),
        "SameSite=Lax".to_string(),
        format!("Max-Age={ttl_secs}"),
    ];
    if secure {
        attrs.push("Secure".to_string());
    }
    attrs.join("; ")
}

pub(in crate::web::management) fn build_session_clear_cookie(secure: bool) -> String {
    let mut attrs = vec![
        format!("{MGMT_SESSION_COOKIE_NAME}="),
        "Path=/api/v1".to_string(),
        "HttpOnly".to_string(),
        "SameSite=Lax".to_string(),
        "Max-Age=0".to_string(),
    ];
    if secure {
        attrs.push("Secure".to_string());
    }
    attrs.join("; ")
}
