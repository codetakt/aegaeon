mod grant_types;

pub use grant_types::{
    canonical_supported_grant_type, canonical_supported_grant_types, default_grant_types,
    is_supported_grant_type, supported_grant_types_csv, validate_supported_grant_types,
    AUTHORIZATION_CODE_GRANT_TYPE, CLIENT_CREDENTIALS_GRANT_TYPE, DEFAULT_GRANT_TYPES,
    DEVICE_CODE_GRANT_TYPE, JWT_BEARER_GRANT_TYPE, REFRESH_TOKEN_GRANT_TYPE, SUPPORTED_GRANT_TYPES,
    TOKEN_EXCHANGE_GRANT_TYPE,
};

/// `SecurityPolicy` holds global OAuth 2.0 hardening flags as per RFC 9700.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderConstraint {
    /// No sender constraint applied.
    None,
    /// Use `DPoP` (Demonstrating Proof-of-Possession).
    DPoP,
    /// Use mutual TLS.
    Mtls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportSecurityPolicy {
    pub enforce_trusted_proxy: bool,
    pub tls_validation_required: bool,
}

impl Default for TransportSecurityPolicy {
    fn default() -> Self {
        Self {
            enforce_trusted_proxy: true,
            tls_validation_required: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenValidationPolicy {
    pub require_scope_subset: bool,
    pub require_audience_match: bool,
}

impl Default for TokenValidationPolicy {
    fn default() -> Self {
        Self {
            require_scope_subset: true,
            require_audience_match: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshSecurityPolicy {
    pub retain_refresh_chain: bool,
    pub enforce_sender_binding: bool,
}

impl Default for RefreshSecurityPolicy {
    fn default() -> Self {
        Self {
            retain_refresh_chain: true,
            enforce_sender_binding: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityPolicy {
    pub require_pkce: bool,
    pub sender_constrained: SenderConstraint,
    pub transport: TransportSecurityPolicy,
    pub token_validation: TokenValidationPolicy,
    pub refresh: RefreshSecurityPolicy,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_pkce: true,
            sender_constrained: SenderConstraint::DPoP,
            transport: TransportSecurityPolicy::default(),
            token_validation: TokenValidationPolicy::default(),
            refresh: RefreshSecurityPolicy::default(),
        }
    }
}

impl SecurityPolicy {
    #[must_use]
    pub const fn enforce_trusted_proxy(&self) -> bool {
        self.transport.enforce_trusted_proxy
    }

    #[must_use]
    pub const fn tls_validation_required(&self) -> bool {
        self.transport.tls_validation_required
    }

    #[must_use]
    pub const fn require_scope_subset(&self) -> bool {
        self.token_validation.require_scope_subset
    }

    #[must_use]
    pub const fn require_audience_match(&self) -> bool {
        self.token_validation.require_audience_match
    }

    #[must_use]
    pub const fn retain_refresh_chain(&self) -> bool {
        self.refresh.retain_refresh_chain
    }

    #[must_use]
    pub const fn enforce_sender_binding(&self) -> bool {
        self.refresh.enforce_sender_binding
    }

    #[must_use]
    pub fn with_sender_binding_enforcement(mut self, enforce_sender_binding: bool) -> Self {
        self.refresh.enforce_sender_binding = enforce_sender_binding;
        self
    }

    #[must_use]
    pub const fn with_sender_constraint(mut self, sender_constrained: SenderConstraint) -> Self {
        self.sender_constrained = sender_constrained;
        self
    }
}

#[cfg(test)]
mod tests;
