//! Kani verification for snapshot versioning

#[cfg(kani)]
mod verification {
    use aegaeon_server::authcode::{AuthCodeStore, AuthorizationCode};

    fn make_code(client: &str, user: &str) -> AuthorizationCode {
        AuthorizationCode::new(
            client.to_string(),
            user.to_string(),
            "https://example.com".to_string(),
            None,
            None,
            None,
            None,
            None,
            0,
            None,
            None,
            None,
            None,
        )
    }

    #[kani::proof]
    fn snapshot_version_increments_on_update() {
        let store = AuthCodeStore::new();

        // Initial code
        let code1 = make_code("client1", "user1");
        let _ = store.store_code(code1);

        let snap1 = store.snapshot();

        // Store a second code
        let code2 = make_code("client2", "user2");
        let _ = store.store_code(code2);

        let snap2 = store.snapshot();

        // Snapshot captured before update must have lower version and fewer codes
        assert!(snap1.version < snap2.version, "Version did not advance");
        assert_eq!(snap1.codes.len() + 1, snap2.codes.len());
    }
}
