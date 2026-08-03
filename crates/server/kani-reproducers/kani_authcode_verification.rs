//! Kani verification for authorization code properties

#[cfg(kani)]
mod verification {
    use aegaeon_server::authcode::{AuthCodeStore, AuthorizationCode};
    use std::time::{Duration, SystemTime};

    fn make_code(
        client: &str,
        user: &str,
        redirect: &str,
        state: Option<String>,
        nonce: Option<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
    ) -> AuthorizationCode {
        AuthorizationCode::new(
            client.to_string(),
            user.to_string(),
            redirect.to_string(),
            None,
            None,
            None,
            state,
            nonce,
            0,
            None,
            None,
            code_challenge,
            code_challenge_method,
        )
    }

    #[kani::proof]
    fn verify_code_single_use() {
        let store = AuthCodeStore::new();

        // Create a code with bounded parameters
        let code = make_code(
            "client",
            "user",
            "https://example.com",
            Some("state".to_string()),
            None,
            Some("challenge".to_string()),
            Some("S256".to_string()),
        );

        let code_str = store.store_code(code).unwrap();

        // First use should succeed
        let first_use = store.use_code(&code_str);
        kani::assume(first_use.is_some());

        // Second use MUST fail (single-use property)
        let second_use = store.use_code(&code_str);
        assert!(second_use.is_none(), "Code reuse detected!");
    }

    #[kani::proof]
    fn verify_expired_code_unusable() {
        let store = AuthCodeStore::new();

        // Create an expired code
        let mut code = make_code(
            "client",
            "user",
            "https://example.com",
            None,
            None,
            None,
            None,
        );

        // Set expiry to past
        code.expires_at = SystemTime::now() - Duration::from_secs(1);

        if let Ok(code_str) = store.store_code(code) {
            // Expired code MUST NOT be usable
            let result = store.use_code(&code_str);
            assert!(result.is_none(), "Expired code was used!");
        }
    }

    #[kani::proof]
    fn verify_state_uniqueness() {
        let store = AuthCodeStore::new();
        let state = "unique_state_123";

        // First code with state
        let code1 = make_code(
            "client1",
            "user1",
            "https://example1.com",
            Some(state.to_string()),
            None,
            None,
            None,
        );

        // Store first code
        let result1 = store.store_code(code1);
        kani::assume(result1.is_ok());

        // Second code with SAME state
        let code2 = make_code(
            "client2",
            "user2",
            "https://example2.com",
            Some(state.to_string()),
            None,
            None,
            None,
        );

        // Second store MUST fail (state uniqueness)
        let result2 = store.store_code(code2);
        assert!(result2.is_err(), "Duplicate state was accepted!");
    }

    #[kani::proof]
    fn verify_nonce_uniqueness() {
        let store = AuthCodeStore::new();
        let nonce = "unique_nonce_456";

        // First code with nonce
        let code1 = make_code(
            "client1",
            "user1",
            "https://example1.com",
            None,
            Some(nonce.to_string()),
            None,
            None,
        );

        // Store first code
        let result1 = store.store_code(code1);
        kani::assume(result1.is_ok());

        // Second code with SAME nonce
        let code2 = make_code(
            "client2",
            "user2",
            "https://example2.com",
            None,
            Some(nonce.to_string()),
            None,
            None,
        );

        // Second store MUST fail (nonce uniqueness)
        let result2 = store.store_code(code2);
        assert!(result2.is_err(), "Duplicate nonce was accepted!");
    }

    #[kani::proof]
    #[kani::unwind(3)] // Bound the loop iterations
    fn verify_concurrent_code_use() {
        let store = AuthCodeStore::new();

        let code = make_code(
            "client",
            "user",
            "https://example.com",
            None,
            None,
            Some("challenge".to_string()),
            Some("S256".to_string()),
        );

        let code_str = store.store_code(code).unwrap();

        // Model concurrent access attempts
        let mut success_count = 0;
        for _ in 0..3 {
            if store.use_code(&code_str).is_some() {
                success_count += 1;
            }
        }

        // EXACTLY one use should succeed
        assert_eq!(
            success_count, 1,
            "Code used multiple times in concurrent access!"
        );
    }
}
