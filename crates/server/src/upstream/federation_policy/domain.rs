#[must_use]
pub(super) fn is_valid_allowlist_domain(value: &str) -> bool {
    if value.is_empty() || value.contains('@') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[must_use]
pub fn extract_email_domain(email: &str) -> Option<String> {
    let (_, domain) = email.trim().rsplit_once('@')?;
    let normalized = domain.trim().to_ascii_lowercase();
    if is_valid_allowlist_domain(&normalized) {
        Some(normalized)
    } else {
        None
    }
}

#[must_use]
pub fn email_allowed_by_domain_allowlist(email: Option<&str>, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let Some(email) = email else {
        return false;
    };
    let Some(domain) = extract_email_domain(email) else {
        return false;
    };
    allowlist.iter().any(|candidate| candidate == &domain)
}
