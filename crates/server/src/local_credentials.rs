mod authentication;
mod environment;
mod identity;
mod mutation;
mod password;
mod recovery_token;
mod rows;
mod state;
mod types;

pub use self::authentication::authenticate_local_user;
pub use self::environment::load_runtime_environment_context;
pub use self::identity::{normalize_email, normalize_subject};
#[cfg(test)]
use self::identity::{normalize_login_identifier, LoginIdentifier};
pub use self::mutation::{
    issue_recovery_token, redeem_recovery_token, revoke_password_credential, revoke_recovery_token,
};
pub(crate) use self::password::verify_password_or_dummy;
pub use self::password::{
    hash_password, validate_password, verify_password, MAX_PASSWORD_BYTES, MIN_PASSWORD_BYTES,
};
pub use self::recovery_token::{
    generate_recovery_token, hash_one_time_token, sanitize_recovery_token_ttl,
    RecoveryTokenTtlPolicy,
};
pub use self::state::load_user_credential_state;
pub use self::types::{
    AuthenticatedLocalUser, IssuedRecoveryToken, PasswordCredentialRecord, RecoveryTokenPurpose,
    RecoveryTokenRecord, RedeemedRecoveryToken, RuntimeEnvironmentContext, UserCredentialState,
    PASSWORD_STATUS_ACTIVE, PASSWORD_STATUS_REVOKED, RECOVERY_STATUS_ACTIVE,
    RECOVERY_STATUS_EXPIRED, RECOVERY_STATUS_REDEEMED, RECOVERY_STATUS_REVOKED,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_password_rejects_short_values() {
        assert_eq!(
            validate_password("short"),
            Err("Password must be at least 12 bytes long")
        );
    }

    #[test]
    fn validate_password_accepts_long_enough_values() {
        assert_eq!(validate_password("long-enough!"), Ok(()));
    }

    #[test]
    fn sanitize_recovery_token_ttl_uses_defaults() {
        let policy = RecoveryTokenTtlPolicy::baseline();
        assert!(
            matches!(
                sanitize_recovery_token_ttl(None, RecoveryTokenPurpose::Activation, policy),
                Ok(ttl) if ttl == crate::config::DEFAULT_ACTIVATION_TOKEN_TTL_SECS as i64
            ),
            "activation TTL should use the default value"
        );
        assert!(
            matches!(
                sanitize_recovery_token_ttl(None, RecoveryTokenPurpose::PasswordReset, policy),
                Ok(ttl) if ttl == crate::config::DEFAULT_PASSWORD_RESET_TOKEN_TTL_SECS as i64
            ),
            "password reset TTL should use the default value"
        );
    }

    #[test]
    fn hash_and_verify_password_roundtrip() {
        let hash_result = hash_password("this-is-a-valid-password");
        assert!(hash_result.is_ok(), "password hashing should succeed");
        let Ok(hash) = hash_result else {
            return;
        };
        assert!(verify_password("this-is-a-valid-password", &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn normalize_login_identifier_prefers_email_shape() {
        assert!(matches!(
            normalize_login_identifier("User@Example.com"),
            Some(LoginIdentifier::Email(email)) if email == "user@example.com"
        ));
    }

    #[test]
    fn normalize_login_identifier_accepts_subject() {
        assert!(matches!(
            normalize_login_identifier("subject-1"),
            Some(LoginIdentifier::Subject(subject)) if subject == "subject-1"
        ));
    }
}
