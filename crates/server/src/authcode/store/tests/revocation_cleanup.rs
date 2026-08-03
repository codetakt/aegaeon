#[test]
fn revoke_tokens_by_subject_returns_zero_for_unknown_subject() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let at = AccessToken::new(
        "client1".into(),
        "user-A".into(),
        Some("openid".into()),
        3600,
    );
    let _ = store_access_token(&store, at);

    let count = store
        .try_revoke_tokens_by_subject("user-UNKNOWN")
        .map_err(|err| format!("in-memory subject revocation should succeed: {err}"))?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn revoke_tokens_by_subject_removes_bearer_meta() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        granted_scopes: vec!["openid".into()],
        audience: "aud".into(),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        ..bearer_meta_input("tok1", "client1", "user-A")
    });
    store_bearer_meta(&store, meta);

    assert!(get_bearer_meta(&store, "tok1").is_some());

    store
        .try_revoke_tokens_by_subject("user-A")
        .map_err(|err| format!("in-memory subject revocation should succeed: {err}"))?;

    assert!(get_bearer_meta(&store, "tok1").is_none());
    Ok(())
}

#[test]
fn client_bound_revocation_rejects_rotated_refresh_owner_mismatch() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let refresh = RefreshToken::new(refresh_input(
        "client-A",
        "user-A",
        Some("offline_access"),
        None,
    ));
    let original = store_refresh_token(&store, refresh);
    let successor = rotate_refresh_token(&store, &original)
        .ok_or_else(|| "initial rotation succeeds".to_string())?;

    assert_eq!(
        store
            .try_revoke_token_for_client(&original, Some("client-B"))
            .map_err(|err| format!("in-memory client-bound revocation should succeed: {err}"))?,
        ClientBoundRevocationOutcome::OwnerMismatch
    );
    assert!(!is_refresh_revoked(&store, &successor.token));

    assert_eq!(
        store
            .try_revoke_token_for_client(&original, Some("client-A"))
            .map_err(|err| format!("in-memory client-bound revocation should succeed: {err}"))?,
        ClientBoundRevocationOutcome::Revoked
    );
    assert!(is_refresh_revoked(&store, &successor.token));
    Ok(())
}

#[test]
fn client_bound_revocation_unknown_token_is_noop() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();

    assert_eq!(
        store
            .try_revoke_token_for_client("unknown-token", Some("client-A"))
            .map_err(|err| format!("in-memory client-bound revocation should succeed: {err}"))?,
        ClientBoundRevocationOutcome::Unknown
    );
    assert!(!store.snapshot().revoked_tokens.contains("unknown-token"));

    let mut access = AccessToken::new("client-A".into(), "user-A".into(), None, 3600);
    access.token = "unknown-token".to_string();
    let _ = store_access_token(&store, access);

    assert!(verify_access_token(&store, "unknown-token").is_some());
    Ok(())
}

#[test]
fn cleanup_expired_removes_revocation_tombstones() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let mut access = AccessToken::new("client-A".into(), "user-A".into(), None, 3600);
    access.token = "revoked-access".to_string();
    let _ = store_access_token(&store, access);

    store
        .try_revoke_token("revoked-access")
        .map_err(|err| format!("in-memory revocation should succeed: {err}"))?;
    assert!(store.snapshot().revoked_tokens.contains("revoked-access"));

    store.try_mutate_state("test_expire_revocation_tombstone", |state| {
        state.revoked_tokens.insert(
            "revoked-access".to_string(),
            SystemTime::now() - Duration::from_secs(1),
        );
    })?;
    store.cleanup_expired();

    assert!(!store.snapshot().revoked_tokens.contains("revoked-access"));
    Ok(())
}

#[test]
fn cleanup_expired_removes_refresh_successor_edges_touching_expired_tokens() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let original = store_refresh_token(
        &store,
        RefreshToken::new(refresh_input(
            "client-A",
            "user-A",
            Some("offline_access"),
            None,
        )),
    );
    let successor = rotate_refresh_token(&store, &original)
        .ok_or_else(|| "initial rotation succeeds".to_string())?;

    store.try_mutate_state("test_expire_original_refresh", |state| {
        state
            .refresh_tokens
            .get_mut(&original)
            .ok_or_else(|| "original refresh exists".to_string())?
            .expires_at = SystemTime::now() - Duration::from_secs(1);
        assert_eq!(
            state.refresh_successors.get(&original),
            Some(&successor.token)
        );
        Ok::<(), String>(())
    })??;

    store.cleanup_expired();

    store.try_with_state("test_assert_original_refresh_cleanup", |state| {
        assert!(!state.refresh_tokens.contains_key(&original));
        assert!(state.refresh_tokens.contains_key(&successor.token));
        assert!(!state.refresh_successors.contains_key(&original));
        assert!(!state
            .refresh_successors
            .values()
            .any(|value| value == &original));
    })?;

    let second_original = store_refresh_token(
        &store,
        RefreshToken::new(refresh_input(
            "client-A",
            "user-A",
            Some("offline_access"),
            None,
        )),
    );
    let second_successor =
        rotate_refresh_token(&store, &second_original)
            .ok_or_else(|| "second rotation succeeds".to_string())?;
    store.try_mutate_state("test_expire_successor_refresh", |state| {
        state
            .refresh_tokens
            .get_mut(&second_successor.token)
            .ok_or_else(|| "successor refresh exists".to_string())?
            .expires_at = SystemTime::now() - Duration::from_secs(1);
        assert_eq!(
            state.refresh_successors.get(&second_original),
            Some(&second_successor.token)
        );
        Ok::<(), String>(())
    })??;

    store.cleanup_expired();

    store.try_with_state("test_assert_successor_refresh_cleanup", |state| {
        assert!(state.refresh_tokens.contains_key(&second_original));
        assert!(!state.refresh_tokens.contains_key(&second_successor.token));
        assert!(!state.refresh_successors.contains_key(&second_original));
        assert!(!state
            .refresh_successors
            .values()
            .any(|value| value == &second_successor.token));
    })?;
    Ok(())
}

#[test]
fn revoking_access_token_with_unrepresentable_expiry_records_bounded_tombstone(
) -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let token = AccessToken {
        token: "overflow-access".to_string(),
        token_type: "Bearer".to_string(),
        client_id: "client-A".to_string(),
        user_id: "user-A".to_string(),
        scope: None,
        expires_in: u64::MAX,
        created_at: std::time::UNIX_EPOCH + Duration::from_secs(1),
        cnf: None,
    };
    let _ = store_access_token(&store, token);

    store
        .try_revoke_token("overflow-access")
        .map_err(|err| format!("in-memory revocation should succeed: {err}"))?;

    assert!(store.snapshot().revoked_tokens.contains("overflow-access"));
    Ok(())
}

#[test]
fn revoke_tokens_by_subject_revokes_refresh_successor_chain() -> Result<(), String> {
    let store = TokenStore::new_process_local_for_tests();
    let refresh = RefreshToken::new(refresh_input(
        "client-A",
        "user-A",
        Some("offline_access"),
        None,
    ));
    let original = store_refresh_token(&store, refresh);
    let successor = rotate_refresh_token(&store, &original)
        .ok_or_else(|| "initial rotation succeeds".to_string())?;

    let count = store
        .try_revoke_tokens_by_subject("user-A")
        .map_err(|err| format!("in-memory subject revocation should succeed: {err}"))?;

    assert!(count >= 1);
    assert!(is_refresh_revoked(&store, &original));
    assert!(is_refresh_revoked(&store, &successor.token));
    Ok(())
}
