pub(super) enum LoginIdentifier {
    Subject(String),
    Email(String),
}

#[must_use]
pub fn normalize_subject(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[must_use]
pub fn normalize_email(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() || !trimmed.contains('@') {
        None
    } else {
        Some(trimmed)
    }
}

pub(super) fn issuer_host_from_url(issuer: &str) -> Option<String> {
    let url = url::Url::parse(issuer).ok()?;
    crate::util::canonical_url_host_port(&url)
}

pub(super) fn normalize_login_identifier(raw_identifier: &str) -> Option<LoginIdentifier> {
    let trimmed = raw_identifier.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains('@') {
        normalize_email(trimmed).map(LoginIdentifier::Email)
    } else {
        normalize_subject(trimmed).map(LoginIdentifier::Subject)
    }
}
