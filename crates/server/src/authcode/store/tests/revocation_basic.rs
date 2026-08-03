// ---------------------------------------------------------------
// TokenStore: revoke_tokens_by_subject
// ---------------------------------------------------------------

#[test]
fn revoke_tokens_by_subject_revokes_matching_access_tokens() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let at1 = AccessToken::new(
        "client1".into(),
        "user-A".into(),
        Some("openid".into()),
        3600,
    );
    let at2 = AccessToken::new(
        "client1".into(),
        "user-B".into(),
        Some("openid".into()),
        3600,
    );
    let token1 = store_access_token(&store, at1);
    let token2 = store_access_token(&store, at2);

    let count = must_ok!(
        store.try_revoke_tokens_by_subject("user-A"),
        "in-memory subject revocation should succeed",
    );
    assert_eq!(count, 1);
    assert!(verify_access_token(&store, &token1).is_none());
    assert!(verify_access_token(&store, &token2).is_some());
    Ok(())
}

#[test]
fn try_revoke_tokens_by_subject_reports_successful_noop() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();

    let count = must_ok!(
        store.try_revoke_tokens_by_subject("user-UNKNOWN"),
        "in-memory token store should confirm no-op revocation",
    );

    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn try_subject_inventory_reports_successful_empty_lists() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();

    let bearer_meta = must_ok!(
        store.try_list_bearer_meta_for_subject("user-UNKNOWN"),
        "in-memory token store should confirm empty bearer inventory",
    );
    let refresh_tokens = must_ok!(
        store.try_list_refresh_tokens_for_subject("user-UNKNOWN"),
        "in-memory token store should confirm empty refresh-token inventory",
    );

    assert!(bearer_meta.is_empty());
    assert!(refresh_tokens.is_empty());
    Ok(())
}

#[test]
fn try_subject_token_revocation_reports_successful_not_found() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();

    let access_revoked = must_ok!(
        store.try_revoke_access_token_for_subject("user-UNKNOWN", "access-UNKNOWN"),
        "in-memory token store should confirm access-token not found",
    );
    let refresh_revoked = must_ok!(
        store.try_revoke_refresh_token_for_subject("user-UNKNOWN", "refresh-UNKNOWN"),
        "in-memory token store should confirm refresh-token not found",
    );

    assert!(!access_revoked);
    assert!(!refresh_revoked);
    Ok(())
}

#[test]
fn try_client_bound_revocation_reports_successful_unknown() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();

    let outcome = must_ok!(
        store.try_revoke_token_for_client("token-UNKNOWN", Some("client-A")),
        "in-memory token store should confirm unknown token",
    );

    assert_eq!(outcome, ClientBoundRevocationOutcome::Unknown);
    Ok(())
}

#[test]
fn revoke_tokens_by_subject_revokes_matching_refresh_tokens() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let rt1 = RefreshToken::new(refresh_input("client1", "user-A", Some("openid"), None));
    let rt2 = RefreshToken::new(refresh_input("client1", "user-B", Some("openid"), None));
    let token1 = store_refresh_token(&store, rt1);
    let token2 = store_refresh_token(&store, rt2);

    let count = must_ok!(
        store.try_revoke_tokens_by_subject("user-A"),
        "in-memory subject revocation should succeed",
    );
    assert_eq!(count, 1);
    assert!(is_refresh_revoked(&store, &token1));
    assert!(!is_refresh_revoked(&store, &token2));
    Ok(())
}

#[test]
fn revoke_tokens_by_subject_cascades_to_child_access_tokens() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let rt = RefreshToken::new(refresh_input("client1", "user-A", Some("openid"), None));
    let rt_str = store_refresh_token(&store, rt);

    let at = AccessToken::new(
        "client1".into(),
        "user-A".into(),
        Some("openid".into()),
        3600,
    );
    let at_str = store_access_token(&store, at);
    bind_refresh_access(&store, &rt_str, &at_str);

    let count = must_ok!(
        store.try_revoke_tokens_by_subject("user-A"),
        "in-memory subject revocation should succeed",
    );
    // refresh + access = at least 2 (access may be counted directly or via cascade)
    assert!(count >= 2);
    assert!(verify_access_token(&store, &at_str).is_none());
    assert!(is_refresh_revoked(&store, &rt_str));
    Ok(())
}

#[test]
fn store_access_for_refresh_parent_binds_family_revocation() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let refresh = RefreshToken::new(refresh_input(
        "client1",
        "user-A",
        Some("read offline_access"),
        None,
    ));
    let refresh_str = store_refresh_token(&store, refresh);
    let mut access = AccessToken::new("client1".into(), "user-A".into(), Some("read".into()), 3600);
    access.token = "exchanged-access".to_string();
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        audience: "client1".into(),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(refresh_str.clone()),
        ..bearer_meta_input(&access.token, &access.client_id, &access.user_id)
    });

    let stored = must_ok!(
        store.store_access_for_refresh_parent(access, meta),
        "access token should bind to active refresh parent",
    );

    assert!(verify_access_token(&store, &stored).is_some());
    assert_eq!(
        must_ok!(
            store.try_revoke_token_for_client(&refresh_str, Some("client1")),
            "in-memory client-bound revocation should succeed",
        ),
        ClientBoundRevocationOutcome::Revoked
    );
    assert!(verify_access_token(&store, &stored).is_none());
    Ok(())
}
