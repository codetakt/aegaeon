use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Canonical account-link identity digest for an upstream OIDC subject.
///
/// The current persistent representation intentionally matches the original
/// callback runtime format so existing links remain addressable.
#[must_use]
pub fn upstream_subject_link_hash(issuer: &str, subject: &str) -> String {
    let mut hasher = aegaeon_crypto::hash::Sha256Hasher::new();
    hasher.update(issuer.as_bytes());
    hasher.update(b"\0");
    hasher.update(subject.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::upstream_subject_link_hash;

    #[test]
    fn upstream_subject_link_hash_binds_issuer_and_subject() {
        let issuer = "https://issuer.example";
        let subject = "subject-123";

        assert_eq!(
            upstream_subject_link_hash(issuer, subject),
            upstream_subject_link_hash(issuer, subject)
        );
        assert_ne!(
            upstream_subject_link_hash(issuer, subject),
            upstream_subject_link_hash("https://other.example", subject)
        );
        assert_ne!(
            upstream_subject_link_hash(issuer, subject),
            upstream_subject_link_hash(issuer, "other-subject")
        );
    }
}
