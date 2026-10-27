/// OIDC End-User subject format; checking never normalizes identity bytes.
pub(crate) fn is_valid_subject(subject: &str) -> bool {
    !subject.is_empty() && subject.len() <= 255 && subject.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::is_valid_subject;

    #[test]
    fn oidc_subject_format_preserves_ascii_domain() {
        for value in ["a", " A ", "Aa", "\t\n\r\u{7f}", &"x".repeat(255)] {
            assert!(is_valid_subject(value));
        }
        for value in ["", "é", "日本語", &"x".repeat(256)] {
            assert!(!is_valid_subject(value));
        }
    }
}
