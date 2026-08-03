use crate::authcode::types::TokenResponse;

pub(super) type TokenExchangeResult<T> = Result<T, TokenExchangeError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TokenExchangeError {
    Structural(AuthorizationCodeTokenExchangeError),
    Grant(TokenGrantError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationCodeTokenExchangeError {
    MissingCode,
    InvalidOrExpiredCode,
}

impl TokenExchangeError {
    pub(super) fn missing_code() -> Self {
        Self::Structural(AuthorizationCodeTokenExchangeError::MissingCode)
    }

    pub(super) fn invalid_or_expired_code() -> Self {
        Self::Structural(AuthorizationCodeTokenExchangeError::InvalidOrExpiredCode)
    }

    pub(super) fn into_token_response_result(self) -> Result<TokenResponse, String> {
        match self {
            Self::Structural(error) => Err(error.legacy_message().to_string()),
            Self::Grant(error) => Ok(error.into()),
        }
    }

    pub(super) fn into_token_response_or_exchange_error(
        self,
    ) -> Result<TokenResponse, AuthorizationCodeTokenExchangeError> {
        match self {
            Self::Structural(error) => Err(error),
            Self::Grant(error) => Ok(error.into()),
        }
    }
}

impl From<TokenGrantError> for TokenExchangeError {
    fn from(error: TokenGrantError) -> Self {
        Self::Grant(error)
    }
}

impl AuthorizationCodeTokenExchangeError {
    const fn legacy_message(self) -> &'static str {
        match self {
            Self::MissingCode => "Missing code",
            Self::InvalidOrExpiredCode => "Invalid or expired code",
        }
    }

    pub(crate) const fn oauth_error_code(self) -> &'static str {
        match self {
            Self::MissingCode => "invalid_request",
            Self::InvalidOrExpiredCode => "invalid_grant",
        }
    }

    pub(crate) const fn oauth_error_description(self) -> &'static str {
        match self {
            Self::MissingCode => "code is required",
            Self::InvalidOrExpiredCode => "invalid or expired code",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TokenGrantError {
    code: TokenGrantErrorCode,
    description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TokenGrantErrorCode {
    InvalidClient,
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    InvalidTarget,
    ServerError,
    UnauthorizedClient,
    UnsupportedGrantType,
}

impl TokenGrantError {
    pub(super) fn without_description(code: TokenGrantErrorCode) -> Self {
        Self {
            code,
            description: None,
        }
    }

    pub(super) fn described(code: TokenGrantErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: Some(description.into()),
        }
    }

    pub(super) fn server(description: impl Into<String>) -> Self {
        Self::described(TokenGrantErrorCode::ServerError, description)
    }

    fn with_optional_description(code: TokenGrantErrorCode, description: Option<String>) -> Self {
        Self { code, description }
    }
}

impl TokenGrantErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::ServerError => "server_error",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
        }
    }
}

impl From<TokenGrantError> for TokenResponse {
    fn from(error: TokenGrantError) -> Self {
        Self::Error {
            error: error.code.as_str().to_string(),
            error_description: error.description,
        }
    }
}

impl From<(String, Option<String>)> for TokenGrantError {
    fn from((code, description): (String, Option<String>)) -> Self {
        match code.as_str() {
            "invalid_request" => {
                Self::with_optional_description(TokenGrantErrorCode::InvalidRequest, description)
            }
            "server_error" => {
                Self::with_optional_description(TokenGrantErrorCode::ServerError, description)
            }
            _ => Self::server("id_token issuance failed"),
        }
    }
}
