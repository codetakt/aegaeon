//! Authorization Code and Token types per RFC 6749/6750/9700.

use std::time::{Duration, SystemTime};

mod access_token;
mod authorization_code;
mod refresh_token;
mod requests;

pub use access_token::{
    AccessToken, BearerTokenMeta, BearerTokenMetaInput, CnfClaim, SenderBinding,
};
pub use authorization_code::{AuthorizationCode, AuthorizationCodeInput};
pub use refresh_token::{RefreshToken, RefreshTokenInput};
pub use requests::{AuthorizationRequest, TokenRequest, TokenResponse};

fn system_time_after_secs(now: SystemTime, seconds: u64) -> Option<SystemTime> {
    now.checked_add(Duration::from_secs(seconds))
}

fn generate_secure_random(len: usize) -> String {
    aegaeon_crypto::rand::random_base64url(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn access_token_unrepresentable_expiry_is_expired() {
        let token = AccessToken {
            token: "access".to_string(),
            token_type: "Bearer".to_string(),
            client_id: "client".to_string(),
            user_id: "user".to_string(),
            scope: None,
            expires_in: u64::MAX,
            created_at: SystemTime::now(),
            cnf: None,
        };

        assert!(token.is_expired());
    }

    #[test]
    fn refresh_token_unrepresentable_ttl_does_not_panic() {
        let before = SystemTime::now();
        let token = RefreshToken::with_ttl(
            RefreshTokenInput::new("client".to_string(), "user".to_string()),
            u64::MAX,
        );

        assert!(token.expires_at >= before);
        assert!(token.expires_at <= SystemTime::now());
    }

    #[test]
    fn refresh_token_rotation_count_saturates() {
        let mut token = RefreshToken::new(RefreshTokenInput::new(
            "client".to_string(),
            "user".to_string(),
        ));
        token.rotation_count = u32::MAX;

        let rotated = token.rotate();

        assert_eq!(rotated.rotation_count, u32::MAX);
    }
}
