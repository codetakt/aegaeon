#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;

use crate::device_authz::VerificationRateLimiter;

use super::super::sha256_hex;

#[cfg(test)]
pub(in crate::web::management) fn management_login_rate_limit_keys(
    remote: SocketAddr,
    email: &str,
) -> [String; 3] {
    management_login_rate_limit_keys_for_subject(&remote.ip().to_string(), email)
}

pub(in crate::web::management) fn management_login_rate_limit_keys_for_subject(
    subject: &str,
    email: &str,
) -> [String; 3] {
    let normalized = email.trim().to_ascii_lowercase();
    let principal = sha256_hex(normalized.as_bytes());
    [
        format!("management-login:ip:{subject}"),
        format!("management-login:principal:{principal}"),
        format!("management-login:pair:{subject}:{principal}"),
    ]
}

pub(in crate::web::management) fn management_bootstrap_rate_limit_keys_for_subject(
    subject: &str,
    email: &str,
    bootstrap_token: Option<&str>,
) -> [String; 4] {
    let normalized = email.trim().to_ascii_lowercase();
    let principal = sha256_hex(normalized.as_bytes());
    let token = bootstrap_token
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map_or_else(
            || "missing".to_string(),
            |token| sha256_hex(token.as_bytes()),
        );
    [
        format!("management-bootstrap:ip:{subject}"),
        format!("management-bootstrap:principal:{principal}"),
        format!("management-bootstrap:token:{token}"),
        format!("management-bootstrap:pair:{subject}:{principal}:{token}"),
    ]
}

#[cfg(test)]
pub(in crate::web::management) fn management_login_rate_limit_allows(
    limiter: &VerificationRateLimiter,
    keys: &[String],
) -> Result<bool, String> {
    limiter.try_check_all(keys.iter().map(String::as_str))
}

pub(in crate::web::management) async fn management_login_rate_limit_allows_async(
    limiter: Arc<VerificationRateLimiter>,
    keys: Vec<String>,
) -> Result<bool, String> {
    limiter.try_check_all_async(keys).await
}
