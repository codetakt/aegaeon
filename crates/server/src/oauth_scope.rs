use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScopeStringError {
    Empty,
    InvalidSeparator,
    InvalidToken(String),
    Duplicate(String),
}

impl fmt::Display for ScopeStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeStringError::Empty => f.write_str("scope must not be empty"),
            ScopeStringError::InvalidSeparator => {
                f.write_str("scope values must be separated by a single ASCII space")
            }
            ScopeStringError::InvalidToken(token) => {
                write!(
                    f,
                    "scope token `{token}` is not a valid RFC 6749 scope-token"
                )
            }
            ScopeStringError::Duplicate(token) => {
                write!(f, "scope contains duplicate token `{token}`")
            }
        }
    }
}

impl std::error::Error for ScopeStringError {}

#[must_use]
pub(crate) fn is_scope_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_scope_token_byte)
}

fn is_scope_token_byte(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e)
}

/// Parse an OAuth scope string according to RFC 6749 `scope-token` syntax.
///
/// This intentionally accepts only ASCII space as a separator. Other Unicode or ASCII whitespace is
/// rejected as part of a malformed token rather than silently normalized.
pub(crate) fn parse_scope_string(value: &str) -> Result<Vec<String>, ScopeStringError> {
    if value.is_empty() {
        return Err(ScopeStringError::Empty);
    }
    if value.starts_with(' ') || value.ends_with(' ') || value.contains("  ") {
        return Err(ScopeStringError::InvalidSeparator);
    }

    let mut seen = BTreeSet::new();
    value
        .split(' ')
        .map(|token| {
            if !is_scope_token(token) {
                return Err(ScopeStringError::InvalidToken(token.to_string()));
            }
            if !seen.insert(token.to_string()) {
                return Err(ScopeStringError::Duplicate(token.to_string()));
            }
            Ok(token.to_string())
        })
        .collect()
}

pub(crate) fn parse_optional_scope_string(
    value: Option<&str>,
) -> Result<Vec<String>, ScopeStringError> {
    value.map_or_else(|| Ok(Vec::new()), parse_scope_string)
}

#[must_use]
pub(crate) fn scope_string(scopes: &[String]) -> Option<String> {
    (!scopes.is_empty()).then(|| scopes.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_space_delimited_scope_tokens() {
        assert_eq!(
            parse_scope_string("openid profile.email").expect("valid scope string"),
            vec!["openid".to_string(), "profile.email".to_string()]
        );
    }

    #[test]
    fn rejects_non_scope_token_separators_and_duplicates() {
        assert!(matches!(
            parse_scope_string("openid  profile"),
            Err(ScopeStringError::InvalidSeparator)
        ));
        assert!(matches!(
            parse_scope_string("openid\tprofile"),
            Err(ScopeStringError::InvalidToken(_))
        ));
        assert!(matches!(
            parse_scope_string("openid openid"),
            Err(ScopeStringError::Duplicate(scope)) if scope == "openid"
        ));
    }

    #[test]
    fn optional_scope_parser_distinguishes_absent_from_empty() {
        assert_eq!(
            parse_optional_scope_string(None).expect("absent scope"),
            Vec::<String>::new()
        );
        assert!(matches!(
            parse_optional_scope_string(Some("")),
            Err(ScopeStringError::Empty)
        ));
    }
}
