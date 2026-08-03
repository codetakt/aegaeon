use super::TokenIssuer;
use crate::authcode::store::{AuthCodeStore, TokenStore};
#[cfg(test)]
use crate::config::DEFAULT_AUTHORIZATION_CODE_TTL_SECS;
use crate::config::{
    valid_access_token_ttl_secs, valid_authorization_code_ttl_secs, valid_refresh_token_ttl_secs,
    ConfigError, RuntimeStateNamespace,
};
use crate::kms::KeyManager;
use crate::oidc::{OidcConfig, OidcSessionStore};
use std::sync::Arc;
use std::time::Duration;

/// Default access token TTL (1 hour).
#[cfg(test)]
const DEFAULT_ACCESS_TOKEN_TTL_SECS: u64 = 3600;
/// Default refresh token TTL (24 hours).
#[cfg(test)]
const DEFAULT_REFRESH_TOKEN_TTL_SECS: u64 = 86400;

fn validate_runtime_ttl(
    key: &str,
    value: u64,
    is_valid: fn(u64) -> bool,
    expectation: &str,
) -> Result<(), ConfigError> {
    if is_valid(value) {
        Ok(())
    } else {
        Err(ConfigError::InvalidNumberRange {
            key: key.to_string(),
            value: value.to_string(),
            expectation: expectation.to_string(),
        })
    }
}

impl TokenIssuer {
    /// Create a token issuer with explicit authorization-code and token stores.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_stores(
        key_manager: Arc<dyn KeyManager>,
        code_store: AuthCodeStore,
        token_store: TokenStore,
    ) -> Self {
        Self {
            code_store,
            token_store,
            key_manager,
            oidc: None,
            oidc_sessions: None,
            issuer: None,
            jwt_access_tokens_enabled: false,
            access_token_ttl_secs: DEFAULT_ACCESS_TOKEN_TTL_SECS,
            refresh_token_ttl_secs: DEFAULT_REFRESH_TOKEN_TTL_SECS,
            authorization_code_ttl_secs: DEFAULT_AUTHORIZATION_CODE_TTL_SECS,
        }
    }

    /// Create a process-local token issuer for unit tests.
    ///
    /// Production code should use [`Self::try_from_shared_store_env_with_ttls`].
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests(key_manager: Arc<dyn KeyManager>) -> Self {
        Self::with_stores(
            key_manager,
            AuthCodeStore::new_process_local_for_tests(),
            TokenStore::new_process_local_for_tests(),
        )
    }

    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_process_local_with_ttls_for_tests(
        key_manager: Arc<dyn KeyManager>,
        access_token_ttl_secs: u64,
        refresh_token_ttl_secs: u64,
        authorization_code_ttl_secs: u64,
    ) -> Self {
        Self {
            access_token_ttl_secs,
            refresh_token_ttl_secs,
            authorization_code_ttl_secs,
            ..Self::with_stores(
                key_manager,
                AuthCodeStore::new_process_local_with_ttl_for_tests(Duration::from_secs(
                    authorization_code_ttl_secs,
                )),
                TokenStore::new_process_local_for_tests(),
            )
        }
    }

    pub fn try_from_shared_store_env_with_ttls(
        key_manager: Arc<dyn KeyManager>,
        access_token_ttl_secs: u64,
        refresh_token_ttl_secs: u64,
        authorization_code_ttl_secs: u64,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        validate_runtime_ttl(
            "access_token_time_to_live_seconds",
            access_token_ttl_secs,
            valid_access_token_ttl_secs,
            "a value in 1..=86400 seconds",
        )?;
        validate_runtime_ttl(
            "refresh_token_time_to_live_seconds",
            refresh_token_ttl_secs,
            valid_refresh_token_ttl_secs,
            "a value in 1..=7776000 seconds",
        )?;
        validate_runtime_ttl(
            "authorization_code_time_to_live_seconds",
            authorization_code_ttl_secs,
            valid_authorization_code_ttl_secs,
            "a value in 1..=600 seconds",
        )?;
        Ok(Self {
            code_store: AuthCodeStore::try_from_shared_store_env_with_ttl(
                Duration::from_secs(authorization_code_ttl_secs),
                runtime_state_namespace,
            )?,
            token_store: TokenStore::try_from_shared_store_env(runtime_state_namespace)?,
            key_manager,
            oidc: None,
            oidc_sessions: None,
            issuer: None,
            jwt_access_tokens_enabled: false,
            access_token_ttl_secs,
            refresh_token_ttl_secs,
            authorization_code_ttl_secs,
        })
    }

    /// Attach OIDC configuration (if enabled) before issuing tokens.
    #[must_use]
    pub fn with_oidc(mut self, oidc: Option<OidcConfig>) -> Self {
        self.oidc = oidc;
        self
    }

    /// Attach the shared OIDC session store (used for `sid` and logout fan-out).
    #[must_use]
    pub fn with_oidc_sessions(mut self, sessions: Option<OidcSessionStore>) -> Self {
        self.oidc_sessions = sessions;
        self
    }

    /// Attach the issuer used for JWT access token issuance.
    #[must_use]
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Enable or disable RFC 9068 JWT access tokens (default is disabled).
    #[must_use]
    pub fn with_jwt_access_tokens_enabled(mut self, enabled: bool) -> Self {
        self.jwt_access_tokens_enabled = enabled;
        self
    }

    /// Return the configured access-token lifetime in seconds.
    #[must_use]
    pub fn access_token_ttl_secs(&self) -> u64 {
        self.access_token_ttl_secs
    }

    /// Return the configured refresh-token lifetime in seconds.
    #[must_use]
    pub fn refresh_token_ttl_secs(&self) -> u64 {
        self.refresh_token_ttl_secs
    }

    /// Return the configured authorization-code lifetime in seconds.
    #[must_use]
    pub fn authorization_code_ttl_secs(&self) -> u64 {
        self.authorization_code_ttl_secs
    }
}
