use std::collections::BTreeSet;
use std::fmt;

pub const AUTHORIZATION_CODE_GRANT_TYPE: &str = "authorization_code";
pub const REFRESH_TOKEN_GRANT_TYPE: &str = "refresh_token";
pub const CLIENT_CREDENTIALS_GRANT_TYPE: &str = "client_credentials";
pub const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

pub const SUPPORTED_GRANT_TYPES: &[&str] = &[
    AUTHORIZATION_CODE_GRANT_TYPE,
    REFRESH_TOKEN_GRANT_TYPE,
    CLIENT_CREDENTIALS_GRANT_TYPE,
    JWT_BEARER_GRANT_TYPE,
    TOKEN_EXCHANGE_GRANT_TYPE,
    DEVICE_CODE_GRANT_TYPE,
];

pub const DEFAULT_GRANT_TYPES: &[&str] = &[
    AUTHORIZATION_CODE_GRANT_TYPE,
    REFRESH_TOKEN_GRANT_TYPE,
    CLIENT_CREDENTIALS_GRANT_TYPE,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantTypeListError {
    Empty,
    Unsupported { value: String },
    Duplicate { value: &'static str },
}

impl fmt::Display for GrantTypeListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "grant allowlist must contain at least one supported grant type"
            ),
            Self::Unsupported { value } => write!(
                f,
                "unsupported grant type {value:?}; supported grant types are: {}",
                supported_grant_types_csv()
            ),
            Self::Duplicate { value } => write!(
                f,
                "grant type {value:?} is duplicated after canonical normalization"
            ),
        }
    }
}

#[must_use]
pub fn canonical_supported_grant_type(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        AUTHORIZATION_CODE_GRANT_TYPE => Some(AUTHORIZATION_CODE_GRANT_TYPE),
        REFRESH_TOKEN_GRANT_TYPE => Some(REFRESH_TOKEN_GRANT_TYPE),
        CLIENT_CREDENTIALS_GRANT_TYPE => Some(CLIENT_CREDENTIALS_GRANT_TYPE),
        JWT_BEARER_GRANT_TYPE => Some(JWT_BEARER_GRANT_TYPE),
        TOKEN_EXCHANGE_GRANT_TYPE => Some(TOKEN_EXCHANGE_GRANT_TYPE),
        DEVICE_CODE_GRANT_TYPE => Some(DEVICE_CODE_GRANT_TYPE),
        _ => None,
    }
}

#[must_use]
pub fn is_supported_grant_type(value: &str) -> bool {
    canonical_supported_grant_type(value).is_some()
}

pub fn canonical_supported_grant_types(
    values: &[String],
) -> Result<Vec<String>, GrantTypeListError> {
    if values.is_empty() {
        return Err(GrantTypeListError::Empty);
    }

    let mut seen = BTreeSet::new();
    for value in values {
        let Some(canonical) = canonical_supported_grant_type(value) else {
            return Err(GrantTypeListError::Unsupported {
                value: value.trim().to_string(),
            });
        };
        if !seen.insert(canonical) {
            return Err(GrantTypeListError::Duplicate { value: canonical });
        }
    }

    Ok(SUPPORTED_GRANT_TYPES
        .iter()
        .filter(|grant| seen.contains(*grant))
        .map(|grant| (*grant).to_string())
        .collect())
}

pub fn validate_supported_grant_types(values: &[String]) -> Result<(), GrantTypeListError> {
    canonical_supported_grant_types(values).map(|_| ())
}

#[must_use]
pub fn default_grant_types() -> Vec<String> {
    DEFAULT_GRANT_TYPES
        .iter()
        .map(|grant| (*grant).to_string())
        .collect()
}

#[must_use]
pub fn supported_grant_types_csv() -> String {
    SUPPORTED_GRANT_TYPES.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn canonicalizes_supported_grant_types() {
        assert_eq!(
            canonical_supported_grant_type(" AUTHORIZATION_CODE "),
            Some(AUTHORIZATION_CODE_GRANT_TYPE)
        );
        assert_eq!(
            canonical_supported_grant_type("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            Some(JWT_BEARER_GRANT_TYPE)
        );
    }

    #[test]
    fn rejects_unknown_and_duplicate_grant_types() {
        assert!(matches!(
            validate_supported_grant_types(&strings(&["authorization_code", "urn:custom"])),
            Err(GrantTypeListError::Unsupported { value }) if value == "urn:custom"
        ));
        assert!(matches!(
            validate_supported_grant_types(&strings(&["authorization_code", "AUTHORIZATION_CODE"])),
            Err(GrantTypeListError::Duplicate { value }) if value == AUTHORIZATION_CODE_GRANT_TYPE
        ));
    }

    #[test]
    fn canonical_grant_types_follow_supported_order() {
        assert_eq!(
            canonical_supported_grant_types(&strings(&[
                TOKEN_EXCHANGE_GRANT_TYPE,
                AUTHORIZATION_CODE_GRANT_TYPE,
            ])),
            Ok(strings(&[
                AUTHORIZATION_CODE_GRANT_TYPE,
                TOKEN_EXCHANGE_GRANT_TYPE
            ]))
        );
    }
}
