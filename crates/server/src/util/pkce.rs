/// RFC 7636 section 4.2: challenge syntax, without asserting an S256 preimage.
/// Values are neither decoded nor normalized.
pub(crate) fn valid_pkce_challenge(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_ascii_grammar_and_length_boundaries() {
        for len in [0, 42, 43, 128, 129] {
            assert_eq!(
                valid_pkce_challenge(&"A".repeat(len)),
                (43..=128).contains(&len)
            );
        }
        for byte in 0_u8..=127 {
            let candidate = format!("{}{}", "A".repeat(42), char::from(byte));
            let expected = byte.is_ascii_alphanumeric() || b"-._~".contains(&byte);
            assert_eq!(valid_pkce_challenge(&candidate), expected, "byte {byte}");
        }
        for non_ascii in ["é", "\u{00a0}", "🔑"] {
            assert!(!valid_pkce_challenge(&format!(
                "{}{non_ascii}",
                "A".repeat(43)
            )));
        }
    }
}
