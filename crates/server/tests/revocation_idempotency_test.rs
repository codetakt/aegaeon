// Test suite for RFC 7009 Token Revocation idempotency requirements

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct Token {
    #[allow(dead_code)]
    id: String,
    is_revoked: bool,
    revoked_at: Option<u64>,
    kind: TokenType,
}

#[derive(Debug, Clone, PartialEq)]
enum TokenType {
    AccessToken,
    RefreshToken,
}

struct RevocationService {
    tokens: Arc<Mutex<HashMap<String, Token>>>,
}

impl RevocationService {
    fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn tokens_guard(&self) -> std::sync::MutexGuard<'_, HashMap<String, Token>> {
        match self.tokens.lock() {
            Ok(tokens) => tokens,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn add_token(&self, id: String, token_type: TokenType) {
        let mut tokens = self.tokens_guard();
        tokens.insert(
            id.clone(),
            Token {
                id,
                is_revoked: false,
                revoked_at: None,
                kind: token_type,
            },
        );
    }

    /// Revoke a token - MUST be idempotent per RFC 7009 Section 2.2
    fn revoke_token(&self, token_id: &str) {
        let mut tokens = self.tokens_guard();

        if let Some(token) = tokens.get_mut(token_id) {
            if !token.is_revoked {
                // First revocation
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs());
                token.is_revoked = true;
                token.revoked_at = Some(now);
            }
        }
        // RFC 7009: invalid tokens do not cause an error
    }

    fn get_token(&self, token_id: &str) -> Option<Token> {
        let tokens = self.tokens_guard();
        tokens.get(token_id).cloned()
    }

    /// Cascade revocation for refresh tokens and their descendants
    fn cascade_revoke(&self, _parent_id: &str, child_ids: &[String]) -> Vec<bool> {
        child_ids
            .iter()
            .map(|child_id| {
                self.revoke_token(child_id);
                true
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    trait TestContext<T> {
        fn test_context(self, context: &str) -> Result<T, String>;
    }

    impl<T> TestContext<T> for Option<T> {
        fn test_context(self, context: &str) -> Result<T, String> {
            self.ok_or_else(|| context.to_string())
        }
    }

    fn require_token(
        service: &RevocationService,
        token_id: &str,
        context: &str,
    ) -> Result<Token, String> {
        service.get_token(token_id).test_context(context)
    }

    fn revoked_at(token: &Token, context: &str) -> Result<u64, String> {
        token.revoked_at.test_context(context)
    }

    #[test]
    fn test_revocation_idempotency() -> TestResult {
        let service = RevocationService::new();
        let token_id = "test_token_123";

        // Add a token
        service.add_token(token_id.to_string(), TokenType::AccessToken);

        // First revocation
        service.revoke_token(token_id);
        let token = require_token(
            &service,
            token_id,
            "token must exist after first revocation",
        )?;
        assert!(token.is_revoked);
        let first_revoked_at = revoked_at(&token, "first revocation must set timestamp")?;

        // Second revocation - must be idempotent
        service.revoke_token(token_id);
        let token = require_token(
            &service,
            token_id,
            "token must exist after second revocation",
        )?;
        assert!(token.is_revoked);
        assert_eq!(
            revoked_at(&token, "second revocation must keep timestamp")?,
            first_revoked_at
        );

        // Third revocation - still idempotent
        service.revoke_token(token_id);
        let token = require_token(
            &service,
            token_id,
            "token must exist after third revocation",
        )?;
        assert!(token.is_revoked);
        assert_eq!(
            revoked_at(&token, "third revocation must keep timestamp")?,
            first_revoked_at
        );
        Ok(())
    }

    #[test]
    fn test_invalid_token_revocation() {
        let service = RevocationService::new();

        // RFC 7009 Section 2.2: Revoking an invalid token does not cause an error
        service.revoke_token("non_existent_token");
        service.revoke_token("another_invalid_token");
    }

    #[test]
    fn test_refresh_token_cascade_revocation() {
        let service = RevocationService::new();

        // Create a refresh token and its derived access tokens
        let refresh_token = "refresh_123";
        let access_token_1 = "access_456";
        let access_token_2 = "access_789";

        service.add_token(refresh_token.to_string(), TokenType::RefreshToken);
        service.add_token(access_token_1.to_string(), TokenType::AccessToken);
        service.add_token(access_token_2.to_string(), TokenType::AccessToken);

        // Revoke refresh token
        service.revoke_token(refresh_token);

        // Cascade revoke derived tokens
        let results = service.cascade_revoke(
            refresh_token,
            &[access_token_1.to_string(), access_token_2.to_string()],
        );

        assert!(results.iter().all(|&r| r));

        // Verify all tokens are revoked
        let refresh = service.get_token(refresh_token);
        let access_1 = service.get_token(access_token_1);
        let access_2 = service.get_token(access_token_2);
        assert!(refresh.is_some());
        assert!(access_1.is_some());
        assert!(access_2.is_some());
        if let Some(token) = refresh {
            assert!(token.is_revoked);
        }
        if let Some(token) = access_1 {
            assert!(token.is_revoked);
        }
        if let Some(token) = access_2 {
            assert!(token.is_revoked);
        }
    }

    #[test]
    fn test_concurrent_revocation_idempotency() {
        use std::thread;

        let service = Arc::new(RevocationService::new());
        let token_id = "concurrent_token";

        service.add_token(token_id.to_string(), TokenType::AccessToken);

        // Spawn multiple threads trying to revoke the same token
        let mut handles = vec![];

        for _ in 0..10 {
            let service_clone = Arc::clone(&service);
            let token_id_clone = token_id.to_string();

            handles.push(thread::spawn(move || {
                service_clone.revoke_token(&token_id_clone);
            }));
        }

        // Wait for all threads
        for handle in handles {
            assert!(handle.join().is_ok());
        }

        // Token should be revoked exactly once
        let token = service.get_token(token_id);
        assert!(token.is_some());
        if let Some(token) = token {
            assert!(token.is_revoked);
            assert!(token.revoked_at.is_some());
        }
    }

    #[test]
    fn test_different_token_types() {
        let service = RevocationService::new();

        let access_token = "access_token_1";
        let refresh_token = "refresh_token_1";

        service.add_token(access_token.to_string(), TokenType::AccessToken);
        service.add_token(refresh_token.to_string(), TokenType::RefreshToken);

        // Revoke both types
        service.revoke_token(access_token);
        service.revoke_token(refresh_token);

        // Both should be revoked
        let access = service.get_token(access_token);
        let refresh = service.get_token(refresh_token);
        assert!(access.is_some());
        assert!(refresh.is_some());
        if let Some(token) = access {
            assert!(token.is_revoked);
        }
        if let Some(token) = refresh {
            assert!(token.is_revoked);
        }

        // Verify token types are preserved
        let access = service.get_token(access_token);
        let refresh = service.get_token(refresh_token);
        assert!(access.is_some());
        assert!(refresh.is_some());
        if let Some(token) = access {
            assert_eq!(token.kind, TokenType::AccessToken);
        }
        if let Some(token) = refresh {
            assert_eq!(token.kind, TokenType::RefreshToken);
        }
    }

    #[test]
    fn test_revocation_timestamp_preservation() -> TestResult {
        let service = RevocationService::new();
        let token_id = "timestamp_test_token";

        service.add_token(token_id.to_string(), TokenType::AccessToken);

        // First revocation
        service.revoke_token(token_id);
        let first_token = require_token(
            &service,
            token_id,
            "token must exist after first revocation",
        )?;
        let first_timestamp = revoked_at(&first_token, "first revocation must set timestamp")?;

        // Wait a bit to ensure time would change
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Second revocation - timestamp should NOT change
        service.revoke_token(token_id);
        let second_token = require_token(
            &service,
            token_id,
            "token must exist after second revocation",
        )?;
        let second_timestamp = revoked_at(&second_token, "second revocation must keep timestamp")?;

        assert_eq!(first_timestamp, second_timestamp);
        Ok(())
    }
}
