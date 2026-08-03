use crate::kms::KeyManagerError;
use aegaeon_jose::raw_json::RawJsonSurface;

pub(in crate::authcode::token) struct JwtTokenParts {
    pub(in crate::authcode::token) header: JwtAccessTokenHeader,
    pub(in crate::authcode::token) payload: JwtAccessTokenPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JwtAccessTokenParseError {
    InvalidToken,
    BackendPolicy(&'static str),
}

impl JwtAccessTokenParseError {
    pub(super) const fn backend_policy(surface: RawJsonSurface) -> Self {
        Self::BackendPolicy(surface.as_str())
    }
}

#[derive(Debug)]
pub(in crate::authcode::token) enum JwtAccessTokenVerificationError {
    KeyManager(KeyManagerError),
    BackendPolicy(&'static str),
}

impl From<KeyManagerError> for JwtAccessTokenVerificationError {
    fn from(err: KeyManagerError) -> Self {
        Self::KeyManager(err)
    }
}

pub(super) fn access_token_parse_result<T>(
    result: Result<T, JwtAccessTokenParseError>,
) -> Result<Option<T>, JwtAccessTokenVerificationError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(JwtAccessTokenParseError::InvalidToken) => Ok(None),
        Err(JwtAccessTokenParseError::BackendPolicy(surface)) => {
            Err(JwtAccessTokenVerificationError::BackendPolicy(surface))
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::authcode::token) struct JwtAccessTokenHeader {
    pub(in crate::authcode::token) alg: Option<String>,
    pub(in crate::authcode::token) typ: Option<String>,
    pub(in crate::authcode::token) kid: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::authcode::token) struct JwtAccessTokenPayload {
    pub(in crate::authcode::token) iss: Option<String>,
    pub(in crate::authcode::token) sub: Option<String>,
    pub(in crate::authcode::token) aud_present: bool,
    pub(in crate::authcode::token) aud: Option<JwtAccessTokenAudience>,
    pub(in crate::authcode::token) exp: Option<u64>,
    pub(in crate::authcode::token) iat: Option<u64>,
    pub(in crate::authcode::token) jti: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::authcode::token) enum JwtAccessTokenAudience {
    Single(String),
    Multiple(Vec<String>),
}
