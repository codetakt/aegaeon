use super::types::RecoveryTokenPurpose;
use crate::config::{
    DEFAULT_ACTIVATION_TOKEN_TTL_SECS, DEFAULT_PASSWORD_RESET_TOKEN_TTL_SECS,
    MAX_RECOVERY_TOKEN_TTL_SECS, MIN_RECOVERY_TOKEN_TTL_SECS,
};
use crate::upstream::random_token;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryTokenTtlPolicy {
    activation_token_default_ttl_secs: i64,
    password_reset_token_default_ttl_secs: i64,
    max_ttl_secs: i64,
}

impl RecoveryTokenTtlPolicy {
    /// # Errors
    ///
    /// Returns an error when the policy itself is outside supported bounds.
    pub fn new(
        activation_token_default_ttl_secs: i64,
        password_reset_token_default_ttl_secs: i64,
        max_ttl_secs: i64,
    ) -> Result<Self, &'static str> {
        let policy = Self {
            activation_token_default_ttl_secs,
            password_reset_token_default_ttl_secs,
            max_ttl_secs,
        };
        if !policy_ttl_is_supported(max_ttl_secs)
            || !policy_ttl_is_supported(activation_token_default_ttl_secs)
            || !policy_ttl_is_supported(password_reset_token_default_ttl_secs)
            || activation_token_default_ttl_secs > max_ttl_secs
            || password_reset_token_default_ttl_secs > max_ttl_secs
        {
            return Err("recovery token TTL policy is out of range");
        }
        Ok(policy)
    }

    #[must_use]
    pub fn baseline() -> Self {
        Self {
            activation_token_default_ttl_secs: DEFAULT_ACTIVATION_TOKEN_TTL_SECS as i64,
            password_reset_token_default_ttl_secs: DEFAULT_PASSWORD_RESET_TOKEN_TTL_SECS as i64,
            max_ttl_secs: MAX_RECOVERY_TOKEN_TTL_SECS as i64,
        }
    }

    #[must_use]
    fn default_ttl_secs(self, purpose: RecoveryTokenPurpose) -> i64 {
        match purpose {
            RecoveryTokenPurpose::Activation => self.activation_token_default_ttl_secs,
            RecoveryTokenPurpose::PasswordReset => self.password_reset_token_default_ttl_secs,
        }
    }
}

impl RecoveryTokenPurpose {
    #[must_use]
    pub fn as_db_value(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::PasswordReset => "password_reset",
        }
    }

    #[must_use]
    pub fn as_audit_label(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::PasswordReset => "password_reset",
        }
    }
}

#[must_use]
pub fn generate_recovery_token() -> String {
    random_token(32)
}

#[must_use]
pub fn hash_one_time_token(token: &str) -> String {
    aegaeon_crypto::hash::sha256_hex(token.trim().as_bytes())
}

/// # Errors
///
/// Returns an error when the requested TTL falls outside the supported bounds.
pub fn sanitize_recovery_token_ttl(
    requested_ttl_secs: Option<i64>,
    purpose: RecoveryTokenPurpose,
    policy: RecoveryTokenTtlPolicy,
) -> Result<i64, &'static str> {
    let ttl = requested_ttl_secs.unwrap_or_else(|| policy.default_ttl_secs(purpose));
    if !request_ttl_is_supported(ttl, policy.max_ttl_secs) {
        return Err("expiresInSeconds is out of range");
    }
    Ok(ttl)
}

fn policy_ttl_is_supported(ttl: i64) -> bool {
    (MIN_RECOVERY_TOKEN_TTL_SECS as i64..=MAX_RECOVERY_TOKEN_TTL_SECS as i64).contains(&ttl)
}

fn request_ttl_is_supported(ttl: i64, max_ttl_secs: i64) -> bool {
    (MIN_RECOVERY_TOKEN_TTL_SECS as i64..=max_ttl_secs).contains(&ttl)
}
