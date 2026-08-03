use std::fmt;

/// Context passed when enforcing `SecurityPolicy` checks against bearer tokens.
#[derive(Clone, Copy)]
pub struct TokenPolicyContext<'a> {
    pub requested_scopes: &'a [&'a str],
    pub resource_audience: Option<&'a str>,
    pub sender_dpop_jkt: Option<&'a str>,
    pub sender_mtls_fingerprint: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BearerTokenValidationError {
    Invalid(String),
    Internal(String),
}

impl BearerTokenValidationError {
    pub(super) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub(super) fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    #[must_use]
    pub const fn is_internal(&self) -> bool {
        matches!(self, Self::Internal(_))
    }

    #[must_use]
    pub const fn public_description(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid bearer token",
            Self::Internal(_) => "access token validation failed",
        }
    }
}

impl fmt::Display for BearerTokenValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for BearerTokenValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenPolicyError {
    Validation(BearerTokenValidationError),
    BearerMetadataUnavailable,
    InsufficientScope { missing_scope: String },
    ResourceAudienceRequired,
    InvalidAudience,
    SenderBindingMissing,
    SenderBindingMismatch,
    RefreshParentRevoked,
    TokenStoreUnavailable(String),
}

impl TokenPolicyError {
    pub(super) fn insufficient_scope(missing_scope: impl Into<String>) -> Self {
        Self::InsufficientScope {
            missing_scope: missing_scope.into(),
        }
    }

    pub(super) const fn sender_binding_missing() -> Self {
        Self::SenderBindingMissing
    }

    pub(super) const fn sender_binding_mismatch() -> Self {
        Self::SenderBindingMismatch
    }

    pub(super) fn token_store_unavailable(error: impl Into<String>) -> Self {
        Self::TokenStoreUnavailable(error.into())
    }

    #[must_use]
    pub const fn is_internal(&self) -> bool {
        match self {
            Self::Validation(error) => error.is_internal(),
            Self::TokenStoreUnavailable(_) => true,
            Self::BearerMetadataUnavailable
            | Self::InsufficientScope { .. }
            | Self::ResourceAudienceRequired
            | Self::InvalidAudience
            | Self::SenderBindingMissing
            | Self::SenderBindingMismatch
            | Self::RefreshParentRevoked => false,
        }
    }

    #[must_use]
    pub fn public_description(&self) -> String {
        match self {
            Self::Validation(error) => error.public_description().to_string(),
            Self::BearerMetadataUnavailable => "bearer token metadata unavailable".to_string(),
            Self::InsufficientScope { missing_scope } => {
                format!("insufficient_scope: {missing_scope}")
            }
            Self::ResourceAudienceRequired => "resource audience required".to_string(),
            Self::InvalidAudience => "invalid_audience".to_string(),
            Self::SenderBindingMissing => "sender_binding_missing".to_string(),
            Self::SenderBindingMismatch => "sender_binding_mismatch".to_string(),
            Self::RefreshParentRevoked => "refresh_parent_revoked".to_string(),
            Self::TokenStoreUnavailable(_) => "token store unavailable".to_string(),
        }
    }
}

impl From<BearerTokenValidationError> for TokenPolicyError {
    fn from(error: BearerTokenValidationError) -> Self {
        Self::Validation(error)
    }
}

impl fmt::Display for TokenPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => write!(f, "{error}"),
            Self::BearerMetadataUnavailable => f.write_str("bearer token metadata unavailable"),
            Self::InsufficientScope { missing_scope } => {
                write!(f, "insufficient_scope: {missing_scope}")
            }
            Self::ResourceAudienceRequired => f.write_str("resource audience required"),
            Self::InvalidAudience => f.write_str("invalid_audience"),
            Self::SenderBindingMissing => f.write_str("sender_binding_missing"),
            Self::SenderBindingMismatch => f.write_str("sender_binding_mismatch"),
            Self::RefreshParentRevoked => f.write_str("refresh_parent_revoked"),
            Self::TokenStoreUnavailable(error) => write!(f, "token_store_unavailable: {error}"),
        }
    }
}

impl std::error::Error for TokenPolicyError {}
