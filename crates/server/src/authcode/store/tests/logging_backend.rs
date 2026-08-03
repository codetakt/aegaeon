#[test]
fn token_store_key_digest_is_domain_separated_and_length_delimited() {
    assert_ne!(token_store_key_digest("ab"), token_store_key_digest("a:b"));
    assert_ne!(
        token_store_key_digest("token"),
        crate::util::secret_log_fingerprint("token")
    );
}

#[test]
fn token_store_logs_only_secret_fingerprints() -> StoreTestResult {
    let access_token = "access-token-material-that-must-not-be-logged";
    let refresh_token = "refresh-token-material-that-must-not-be-logged";
    let now = SystemTime::now();
    let expires_at = now + Duration::from_secs(60);
    let store = TokenStore::new_process_local_for_tests();
    let access = AccessToken {
        token: access_token.to_string(),
        token_type: "Bearer".to_string(),
        client_id: "test-client".to_string(),
        user_id: "user".to_string(),
        scope: Some("read".to_string()),
        expires_in: 60,
        created_at: now,
        cnf: None,
    };
    let mut refresh = RefreshToken::with_ttl(
        refresh_input("test-client", "user", Some("read"), None),
        60,
    );
    refresh.token = refresh_token.to_string();
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access_token.to_string(),
        issued_at: now,
        expires_at,
        refresh_parent: Some(refresh_token.to_string()),
        ..bearer_meta_input(access_token, "test-client", "user")
    });
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = CaptureMakeWriter {
        buf: Arc::clone(&buffer),
    };
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .json()
        .with_writer(writer)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let result = store.store_issued_grant(access, Some(refresh), meta);
        assert!(result.is_ok());
    });

    let logs = {
        let bytes = buffer
            .lock()
            .map_err(|err| format!("test log buffer should not be poisoned: {err}"))?
            .clone();
        String::from_utf8(bytes).unwrap_or_else(|_| String::new())
    };
    assert!(!logs.contains(access_token), "access token leaked: {logs}");
    assert!(
        !logs.contains(refresh_token),
        "refresh token leaked: {logs}"
    );
    assert!(logs.contains("access_hash"), "missing access hash: {logs}");
    assert!(
        logs.contains("refresh_hash"),
        "missing refresh hash: {logs}"
    );
    assert!(logs.contains(&crate::util::secret_log_fingerprint(access_token)));
    assert!(logs.contains(&crate::util::secret_log_fingerprint(refresh_token)));
    Ok(())
}

#[test]
fn try_token_lookups_report_backend_unavailable() -> StoreTestResult {
    let store = redis_token_store_for_test("redis://127.0.0.1:1/");

    let access_err = must_err!(
        store.try_verify_access_token("token"),
        "unavailable Redis token store must be reported",
    );
    let meta_err = must_err!(
        store.try_get_bearer_meta("token"),
        "unavailable Redis token store must be reported",
    );
    let refresh_err = must_err!(
        store.try_is_refresh_revoked("refresh"),
        "unavailable Redis token store must be reported",
    );
    let snapshot_err = must_err!(
        store.try_snapshot(),
        "unavailable Redis token store must be reported",
    );
    let known_owner_err = must_err!(
        store.try_known_token_client_id("token"),
        "unavailable Redis token store must be reported",
    );
    let active_owner_err = must_err!(
        store.try_active_token_client_id("token"),
        "unavailable Redis token store must be reported",
    );
    let revoke_err = must_err!(
        store.try_revoke_token("token"),
        "unavailable Redis token store must be reported",
    );
    let subject_revoke_err = must_err!(
        store.try_revoke_tokens_by_subject("subject"),
        "unavailable Redis token store must be reported",
    );
    let subject_access_revoke_err = must_err!(
        store.try_revoke_access_token_for_subject("subject", "token"),
        "unavailable Redis token store must be reported",
    );
    let subject_refresh_revoke_err = must_err!(
        store.try_revoke_refresh_token_for_subject("subject", "refresh"),
        "unavailable Redis token store must be reported",
    );
    let cleanup_err = must_err!(
        store.try_cleanup_expired(),
        "unavailable Redis token store must be reported",
    );

    for err in [
        access_err,
        meta_err,
        refresh_err,
        snapshot_err,
        known_owner_err,
        active_owner_err,
        revoke_err,
        subject_revoke_err,
        subject_access_revoke_err,
        subject_refresh_revoke_err,
        cleanup_err,
    ] {
        assert!(err.contains("token store backend unavailable"));
    }
    Ok(())
}

#[test]
fn try_auth_code_monitoring_reports_backend_unavailable() -> StoreTestResult {
    let store = redis_auth_code_store_for_test("redis://127.0.0.1:1/");

    let snapshot_err = must_err!(
        store.try_snapshot(),
        "unavailable Redis authorization-code store must be reported",
    );
    let state_count_err = must_err!(
        store.try_state_count(),
        "unavailable Redis authorization-code store must be reported",
    );
    let nonce_count_err = must_err!(
        store.try_nonce_count(),
        "unavailable Redis authorization-code store must be reported",
    );

    for err in [snapshot_err, state_count_err, nonce_count_err] {
        assert!(err.contains("authorization code store backend unavailable"));
    }
    Ok(())
}
