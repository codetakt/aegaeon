#[test]
fn store_access_for_refresh_parent_accepts_dpop_thumbprint_uri_equivalence() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let parent_jkt = "parent-jkt".to_string();
    let mut refresh = RefreshToken::new(refresh_input(
        "client1",
        "user-A",
        Some("read offline_access"),
        None,
    ));
    refresh.sender_binding = Some(SenderBinding::DPoP {
        jkt: parent_jkt.clone(),
    });
    let refresh_str = store_refresh_token(&store, refresh);
    let mut access = AccessToken::new("client1".into(), "user-A".into(), Some("read".into()), 3600);
    access.token = "sender-bound-access".to_string();
    access.cnf = Some(CnfClaim::Jkt(parent_jkt.clone()));
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        audience: "client1".into(),
        sender_binding: Some(SenderBinding::DPoP {
            jkt: crate::util::jwk_thumbprint_uri_from_jkt(&parent_jkt),
        }),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(refresh_str),
        ..bearer_meta_input(&access.token, &access.client_id, &access.user_id)
    });

    let stored = must_ok!(
        store.store_access_for_refresh_parent(access, meta),
        "equivalent DPoP thumbprint forms should bind",
    );

    assert!(verify_access_token(&store, &stored).is_some());
    Ok(())
}

#[test]
fn store_access_for_refresh_parent_rejects_sender_binding_mismatch() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let mut refresh = RefreshToken::new(refresh_input(
        "client1",
        "user-A",
        Some("read offline_access"),
        None,
    ));
    refresh.sender_binding = Some(SenderBinding::DPoP {
        jkt: "parent-jkt".into(),
    });
    let refresh_str = store_refresh_token(&store, refresh);
    let mut access = AccessToken::new("client1".into(), "user-A".into(), Some("read".into()), 3600);
    access.token = "sender-mismatch-access".to_string();
    access.cnf = Some(CnfClaim::Jkt("child-jkt".into()));
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        audience: "client1".into(),
        sender_binding: Some(SenderBinding::DPoP {
            jkt: "child-jkt".into(),
        }),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(refresh_str),
        ..bearer_meta_input(&access.token, &access.client_id, &access.user_id)
    });

    let err = must_err!(
        store.store_access_for_refresh_parent(access, meta),
        "mismatched sender binding should fail closed",
    );

    assert_eq!(
        err,
        "bearer metadata sender_binding must match refresh_parent"
    );
    Ok(())
}

#[test]
fn store_access_for_refresh_parent_rejects_access_cnf_mismatch() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let mut refresh = RefreshToken::new(refresh_input(
        "client1",
        "user-A",
        Some("read offline_access"),
        None,
    ));
    refresh.sender_binding = Some(SenderBinding::DPoP {
        jkt: "parent-jkt".into(),
    });
    let refresh_str = store_refresh_token(&store, refresh);
    let mut access = AccessToken::new("client1".into(), "user-A".into(), Some("read".into()), 3600);
    access.token = "cnf-mismatch-access".to_string();
    access.cnf = Some(CnfClaim::Jkt("child-jkt".into()));
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        audience: "client1".into(),
        sender_binding: Some(SenderBinding::DPoP {
            jkt: "parent-jkt".into(),
        }),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(refresh_str),
        ..bearer_meta_input(&access.token, &access.client_id, &access.user_id)
    });

    let err = must_err!(
        store.store_access_for_refresh_parent(access, meta),
        "mismatched access token confirmation should fail closed",
    );

    assert_eq!(
        err,
        "bearer metadata sender_binding must match the access token confirmation"
    );
    Ok(())
}

#[test]
fn store_access_for_refresh_parent_rejects_owner_scope_or_resource_mismatch() {
    let store = TokenStore::new_process_local_for_tests();
    let refresh = RefreshToken::new(refresh_input(
        "client1",
        "user-A",
        Some("read offline_access"),
        None,
    ));
    let refresh_str = store_refresh_token(&store, refresh);

    let mut wrong_owner =
        AccessToken::new("client2".into(), "user-A".into(), Some("read".into()), 3600);
    wrong_owner.token = "wrong-owner-access".to_string();
    let wrong_owner_meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: wrong_owner.token.clone(),
        client_id: wrong_owner.client_id.clone(),
        user_id: wrong_owner.user_id.clone(),
        audience: "client1".into(),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(refresh_str.clone()),
        ..bearer_meta_input(&wrong_owner.token, &wrong_owner.client_id, &wrong_owner.user_id)
    });
    assert!(store
        .store_access_for_refresh_parent(wrong_owner, wrong_owner_meta)
        .is_err());

    let mut scope_escalation = AccessToken::new(
        "client1".into(),
        "user-A".into(),
        Some("write".into()),
        3600,
    );
    scope_escalation.token = "scope-escalation-access".to_string();
    let scope_escalation_meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: scope_escalation.token.clone(),
        client_id: scope_escalation.client_id.clone(),
        user_id: scope_escalation.user_id.clone(),
        granted_scopes: vec!["write".into()],
        audience: "client1".into(),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(refresh_str.clone()),
        ..bearer_meta_input(
            &scope_escalation.token,
            &scope_escalation.client_id,
            &scope_escalation.user_id,
        )
    });
    assert!(store
        .store_access_for_refresh_parent(scope_escalation, scope_escalation_meta)
        .is_err());

    let mut resource_mismatch =
        AccessToken::new("client1".into(), "user-A".into(), Some("read".into()), 3600);
    resource_mismatch.token = "resource-mismatch-access".to_string();
    let resource_mismatch_meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: resource_mismatch.token.clone(),
        client_id: resource_mismatch.client_id.clone(),
        user_id: resource_mismatch.user_id.clone(),
        audience: "https://other.example.com".into(),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(refresh_str),
        ..bearer_meta_input(
            &resource_mismatch.token,
            &resource_mismatch.client_id,
            &resource_mismatch.user_id,
        )
    });
    assert!(store
        .store_access_for_refresh_parent(resource_mismatch, resource_mismatch_meta)
        .is_err());
}

#[test]
fn store_issued_grant_rejects_access_cnf_mismatch() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let mut access = AccessToken::new("client1".into(), "user-A".into(), Some("read".into()), 3600);
    access.token = "issued-cnf-mismatch-access".to_string();
    access.cnf = Some(CnfClaim::Jkt("access-jkt".into()));
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        audience: "client1".into(),
        sender_binding: Some(SenderBinding::DPoP {
            jkt: "metadata-jkt".into(),
        }),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        ..bearer_meta_input(&access.token, &access.client_id, &access.user_id)
    });

    let err = must_err!(
        store.store_issued_grant(access, None, meta),
        "mismatched access confirmation should fail closed",
    );

    assert_eq!(
        err,
        "bearer metadata sender_binding must match the access token confirmation"
    );
    assert!(verify_access_token(&store, "issued-cnf-mismatch-access").is_none());
    assert!(get_bearer_meta(&store, "issued-cnf-mismatch-access").is_none());
    Ok(())
}

#[test]
fn store_issued_grant_rejects_refresh_resource_mismatch() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let mut access = AccessToken::new("client1".into(), "user-A".into(), Some("read".into()), 3600);
    access.token = "issued-resource-mismatch-access".to_string();
    let mut refresh = RefreshToken::new(refresh_input(
        "client1",
        "user-A",
        Some("read"),
        Some("https://api.example.com"),
    ));
    refresh.token = "issued-resource-mismatch-refresh".to_string();
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        audience: "https://other.example.com".into(),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(refresh.token.clone()),
        ..bearer_meta_input(&access.token, &access.client_id, &access.user_id)
    });

    let err = must_err!(
        store.store_issued_grant(access, Some(refresh), meta),
        "refresh resource mismatch should fail closed",
    );

    assert_eq!(
        err,
        "bearer metadata audience must match refresh token resource"
    );
    assert!(verify_access_token(&store, "issued-resource-mismatch-access").is_none());
    assert!(get_refresh_token(&store, "issued-resource-mismatch-refresh").is_none());
    Ok(())
}

#[test]
fn store_refreshed_grant_rejects_access_cnf_mismatch() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let parent_jkt = "parent-jkt".to_string();
    let mut previous_refresh = RefreshToken::new(refresh_input(
        "client1",
        "user-A",
        Some("read"),
        Some("https://api.example.com"),
    ));
    previous_refresh.token = "previous-refresh".to_string();
    previous_refresh.sender_binding = Some(SenderBinding::DPoP {
        jkt: parent_jkt.clone(),
    });
    let previous_refresh_str = store_refresh_token(&store, previous_refresh);
    let mut new_refresh = RefreshToken::new(refresh_input(
        "client1",
        "user-A",
        Some("read"),
        Some("https://api.example.com"),
    ));
    new_refresh.token = "new-refresh".to_string();
    new_refresh.sender_binding = Some(SenderBinding::DPoP {
        jkt: parent_jkt.clone(),
    });
    let mut access = AccessToken::new("client1".into(), "user-A".into(), Some("read".into()), 3600);
    access.token = "refreshed-cnf-mismatch-access".to_string();
    access.cnf = Some(CnfClaim::Jkt("access-jkt".into()));
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        audience: "https://api.example.com".into(),
        sender_binding: Some(SenderBinding::DPoP {
            jkt: parent_jkt.clone(),
        }),
        expires_at: SystemTime::now() + Duration::from_secs(3600),
        refresh_parent: Some(new_refresh.token.clone()),
        ..bearer_meta_input(&access.token, &access.client_id, &access.user_id)
    });

    let err = must_err!(
        store.store_refreshed_grant(&previous_refresh_str, access, new_refresh, meta),
        "mismatched access confirmation should fail closed",
    );

    assert_eq!(err, RefreshRotationError::InconsistentGrant);
    assert!(get_refresh_token(&store, &previous_refresh_str).is_some());
    assert!(get_refresh_token(&store, "new-refresh").is_none());
    assert!(verify_access_token(&store, "refreshed-cnf-mismatch-access").is_none());
    Ok(())
}
