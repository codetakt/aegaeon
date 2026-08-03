#[cfg(kani)]
mod verification {
    use aegaeon_server::authcode::{AccessToken, RefreshToken, TokenStore};
    use std::time::{Duration, SystemTime};

    // Verify that an expired access token is rejected
    #[kani::proof]
    fn expired_access_token_rejected() {
        let store = TokenStore::new();

        // Bound the expiration window to keep time finite
        let expires_in: u64 = 5;
        let mut token =
            AccessToken::new("client".to_string(), "user".to_string(), None, expires_in);
        // Make the token expire by shifting creation time into the past
        token.created_at = SystemTime::now() - Duration::from_secs(expires_in + 1);

        let token_str = store
            .try_store_access_token(token)
            .expect("in-memory access-token store");
        let result = store.verify_access_token(&token_str);
        assert!(result.is_none(), "Expired token was accepted");
    }

    // Verify that revoking a token prevents its use
    #[kani::proof]
    fn revoked_access_token_rejected() {
        let store = TokenStore::new();

        // Single token keeps store size finite
        let token = AccessToken::new("client".to_string(), "user".to_string(), None, 10);
        let token_str = store
            .try_store_access_token(token)
            .expect("in-memory access-token store");

        store.revoke_token(&token_str);
        let result = store.verify_access_token(&token_str);
        assert!(result.is_none(), "Revoked token was accepted");
    }

    // Verify refresh token rotation and single-use property
    #[kani::proof]
    fn refresh_token_rotation_bounds() {
        let store = TokenStore::new();
        let mut token = RefreshToken::new(
            "client".to_string(),
            "user".to_string(),
            None,
            None,
            None,
            0,
            None,
        );
        // Bound expiration close to now
        token.expires_at = SystemTime::now() + Duration::from_secs(1);
        let token_str = store
            .try_store_refresh_token(token)
            .expect("in-memory refresh-token store");

        // First rotation succeeds
        let first = store
            .try_rotate_refresh_token(&token_str)
            .expect("in-memory refresh-token rotation");
        kani::assume(first.is_some());
        let first_token = first.unwrap();

        // Second rotation of original token should fail and revoke it
        let second = store
            .try_rotate_refresh_token(&token_str)
            .expect("in-memory refresh-token rotation");
        assert!(second.is_none(), "Old refresh token was rotated twice");

        // Reuse of the original token revokes the whole refresh-token family.
        let third = store
            .try_rotate_refresh_token(&first_token.token)
            .expect("in-memory refresh-token rotation");
        assert!(
            third.is_none(),
            "Refresh successor remained usable after family revocation"
        );
    }
}
