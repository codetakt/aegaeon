#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_token_store_shares_refresh_rotation_and_revocation() -> StoreTestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let url = url.trim();
    clear_redis_token_store_for_test(url);

    let store_a = redis_token_store_for_test(url);
    let store_b = redis_token_store_for_test(url);
    let suffix = aegaeon_crypto::rand::random_base64url(8);
    let access_1 = format!("access-{suffix}-1");
    let refresh_1 = format!("refresh-{suffix}-1");
    let access_2 = format!("access-{suffix}-2");
    let refresh_2 = format!("refresh-{suffix}-2");
    let access_3 = format!("access-{suffix}-3");
    let access_4 = format!("access-{suffix}-4");
    let refresh_3 = format!("refresh-{suffix}-3");
    let access_5 = format!("access-{suffix}-5");
    let access_6 = format!("access-{suffix}-6");
    let refresh_4 = format!("refresh-{suffix}-4");
    let access_7 = format!("access-{suffix}-7");
    let access_8 = format!("access-{suffix}-8");
    let refresh_5 = format!("refresh-{suffix}-5");
    let access_9 = format!("access-{suffix}-9");
    let refresh_6 = format!("refresh-{suffix}-6");

    must_ok!(
        store_a.store_issued_grant(
            make_access_token(&access_1),
            Some(make_refresh_token(&refresh_1)),
            make_bearer_meta(&access_1, Some(&refresh_1)),
        ),
        "store initial grant",
    );

    assert!(verify_access_token(&store_b, &access_1).is_some());
    assert_eq!(
        must_some!(
            get_bearer_meta(&store_b, &access_1),
            "shared bearer metadata",
        )
            .refresh_parent
            .as_deref(),
        Some(refresh_1.as_str())
    );
    must_ok!(
        store_a.try_replace_refresh_token_record(make_refresh_token(&refresh_3)),
        "store standalone refresh token",
    );
    must_ok!(
        store_b.try_set_refresh_sender_binding(
            &refresh_3,
            Some(SenderBinding::DPoP {
                jkt: "test-jkt".to_string(),
            }),
        ),
        "set refresh sender binding",
    );
    assert_eq!(
        must_some!(get_refresh_token(&store_a, &refresh_3), "shared refresh token").sender_binding,
        Some(SenderBinding::DPoP {
            jkt: "test-jkt".to_string(),
        })
    );
    let refresh_3_successor = must_some!(
        must_ok!(
            store_b.try_rotate_refresh_token(&refresh_3),
            "shared token store should rotate standalone refresh",
        ),
        "standalone refresh should rotate",
    );
    assert!(is_refresh_revoked(&store_a, &refresh_3));
    assert!(get_refresh_token(&store_a, &refresh_3_successor.token).is_some());

    must_ok!(
        store_b.store_refreshed_grant(
            &refresh_1,
            make_access_token(&access_2),
            make_refresh_token(&refresh_2),
            make_bearer_meta(&access_2, Some(&refresh_2)),
        ),
        "store rotated grant",
    );

    assert!(is_refresh_revoked(&store_a, &refresh_1));
    assert!(get_refresh_token(&store_a, &refresh_2).is_some());
    must_ok!(
        store_a.store_access_for_refresh_parent(
            make_access_token(&access_3),
            make_bearer_meta(&access_3, Some(&refresh_2)),
        ),
        "store access for active refresh parent",
    );
    assert!(verify_access_token(&store_b, &access_3).is_some());
    must_ok!(
        store_b.try_replace_access_token_record(make_access_token(&access_4)),
        "store direct access token",
    );
    must_ok!(
        store_a.try_bind_refresh_access(&refresh_2, &access_4),
        "bind access to refresh parent",
    );
    assert!(verify_access_token(&store_b, &access_4).is_some());

    assert!(matches!(
        store_a.prepare_refresh_rotation(&refresh_1),
        Err(RefreshRotationError::Reused)
    ));
    assert!(get_refresh_token(&store_b, &refresh_2).is_none());
    assert!(verify_access_token(&store_b, &access_3).is_none());
    assert!(verify_access_token(&store_b, &access_4).is_none());

    must_ok!(
        store_b.try_revoke_token_for_client(&access_2, Some("test-client")),
        "shared token store should revoke for owner",
    );
    assert!(verify_access_token(&store_a, &access_2).is_none());

    must_ok!(
        store_a.store_issued_grant(
            make_access_token(&access_5),
            Some(make_refresh_token(&refresh_4)),
            make_bearer_meta(&access_5, Some(&refresh_4)),
        ),
        "store refresh revocation grant",
    );
    must_ok!(
        store_b.store_access_for_refresh_parent(
            make_access_token(&access_6),
            make_bearer_meta(&access_6, Some(&refresh_4)),
        ),
        "store refresh child access",
    );
    assert_eq!(
        must_ok!(
            store_a.try_revoke_token_for_client(&refresh_4, Some("test-client")),
            "shared token store should revoke refresh for owner",
        ),
        ClientBoundRevocationOutcome::Revoked
    );
    assert!(get_refresh_token(&store_b, &refresh_4).is_none());
    assert!(verify_access_token(&store_b, &access_5).is_none());
    assert!(verify_access_token(&store_b, &access_6).is_none());

    must_ok!(
        store_a.try_replace_access_token_record(make_access_token(&access_7)),
        "store subject access token",
    );
    assert!(must_ok!(
        store_b.try_revoke_access_token_for_subject("user", &access_7),
        "shared token store should revoke subject access",
    ));
    assert!(verify_access_token(&store_a, &access_7).is_none());

    must_ok!(
        store_a.store_issued_grant(
            make_access_token(&access_8),
            Some(make_refresh_token(&refresh_5)),
            make_bearer_meta(&access_8, Some(&refresh_5)),
        ),
        "store subject refresh grant",
    );
    assert!(must_ok!(
        store_b.try_revoke_refresh_token_for_subject("user", &refresh_5),
        "shared token store should revoke subject refresh",
    ));
    assert!(get_refresh_token(&store_a, &refresh_5).is_none());
    assert!(verify_access_token(&store_a, &access_8).is_none());

    must_ok!(
        store_a.store_issued_grant(
            make_access_token(&access_9),
            Some(make_refresh_token(&refresh_6)),
            make_bearer_meta(&access_9, Some(&refresh_6)),
        ),
        "store subject-wide grant",
    );
    let revoked_count = must_ok!(
        store_b.try_revoke_tokens_by_subject("user"),
        "shared token store should revoke subject-wide",
    );
    assert!(revoked_count >= 2);
    assert!(get_refresh_token(&store_a, &refresh_6).is_none());
    assert!(verify_access_token(&store_a, &access_9).is_none());

    clear_redis_token_store_for_test(url);
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_rotation_expired_branch_deindexes_previous_refresh() -> StoreTestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let url = url.trim();
    clear_redis_token_store_for_test(url);

    let store = redis_token_store_for_test(url);
    let suffix = aegaeon_crypto::rand::random_base64url(8);
    let refresh = format!("refresh-expired-rotation-{suffix}");
    let mut expired_refresh = make_refresh_token(&refresh);
    expired_refresh.expires_at = SystemTime::now()
        .checked_sub(Duration::from_secs(1))
        .ok_or_else(|| "test clock should allow expired refresh construction".to_string())?;

    must_ok!(
        store.try_replace_refresh_token_record(expired_refresh),
        "store expired refresh token",
    );

    let subject_refresh_key = format!(
        "token-store:v3:{{tokens}}:subject-refresh:{}",
        token_store_key_digest("user")
    );
    let refresh_expiry_key = "token-store:v3:{tokens}:expiry:refresh";
    let mut conn = redis::Client::open(url)
        .map_err(|err| format!("open redis client: {err:?}"))?
        .get_connection()
        .map_err(|err| format!("open redis connection: {err:?}"))?;
    let subject_members_before = redis::cmd("SMEMBERS")
        .arg(&subject_refresh_key)
        .query::<Vec<String>>(&mut conn)
        .map_err(|err| format!("read subject refresh index before rotation: {err:?}"))?;
    assert!(
        subject_members_before.contains(&refresh),
        "stored refresh token should be present in subject refresh index before rotation"
    );

    let rotated = must_ok!(
        store.try_rotate_refresh_token(&refresh),
        "expired refresh rotation should be handled without storage failure",
    );
    assert!(
        rotated.is_none(),
        "expired refresh rotation should not mint a successor refresh token"
    );
    assert!(get_refresh_token(&store, &refresh).is_none());

    let subject_members_after = redis::cmd("SMEMBERS")
        .arg(&subject_refresh_key)
        .query::<Vec<String>>(&mut conn)
        .map_err(|err| format!("read subject refresh index after rotation: {err:?}"))?;
    let expiry_score_after = redis::cmd("ZSCORE")
        .arg(refresh_expiry_key)
        .arg(&refresh)
        .query::<Option<f64>>(&mut conn)
        .map_err(|err| format!("read refresh expiry index after rotation: {err:?}"))?;
    assert!(
        !subject_members_after.contains(&refresh),
        "expired refresh rotation must remove the previous token from subject refresh index"
    );
    assert!(
        expiry_score_after.is_none(),
        "expired refresh rotation must remove the previous token from refresh expiry index"
    );

    clear_redis_token_store_for_test(url);
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_authorization_code_grant_commit_consumes_code_and_stores_grant_atomically(
) -> StoreTestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let url = url.trim();
    clear_redis_token_store_for_test(url);

    let code_store = redis_auth_code_store_for_test(url);
    let token_store = redis_token_store_for_test(url);
    let suffix = aegaeon_crypto::rand::random_base64url(16);
    let mut code = make_test_code(
        Some(&format!("state-atomic-{suffix}")),
        Some(&format!("nonce-atomic-{suffix}")),
    );
    code.code = format!("code-atomic-{suffix}");
    let expected_code_payload = must_ok!(
        serde_json::to_string(&code).map_err(|err| err.to_string()),
        "serialize expected authorization code",
    );
    let code_str = must_ok!(
        code_store.store_code_typed(code.clone()),
        "store authorization code"
    );

    let access = format!("access-atomic-{suffix}");
    let refresh = format!("refresh-atomic-{suffix}");
    let (committed_access, committed_refresh) = must_ok!(
        token_store.store_issued_authorization_code_grant(AuthorizationCodeGrantCommit::new(
            code_store.clone(),
            code_str.clone(),
            expected_code_payload.clone(),
            make_access_token(&access),
            Some(make_refresh_token(&refresh)),
            make_bearer_meta(&access, Some(&refresh)),
            None,
        )),
        "atomic authorization-code grant commit",
    );

    assert_eq!(committed_access, access);
    assert_eq!(committed_refresh.as_deref(), Some(refresh.as_str()));
    assert!(
        must_ok!(code_store.try_get_code(&code_str), "authorization code lookup").is_none(),
        "committed authorization code must be consumed"
    );
    assert!(verify_access_token(&token_store, &access).is_some());
    assert!(get_refresh_token(&token_store, &refresh).is_some());
    assert_eq!(
        must_some!(
            get_bearer_meta(&token_store, &access),
            "committed bearer metadata",
        )
        .refresh_parent
        .as_deref(),
        Some(refresh.as_str())
    );

    let duplicate_access = format!("access-atomic-{suffix}-duplicate");
    let duplicate_refresh = format!("refresh-atomic-{suffix}-duplicate");
    let duplicate = must_err!(
        token_store.store_issued_authorization_code_grant(AuthorizationCodeGrantCommit::new(
            code_store.clone(),
            code_str.clone(),
            expected_code_payload.clone(),
            make_access_token(&duplicate_access),
            Some(make_refresh_token(&duplicate_refresh)),
            make_bearer_meta(&duplicate_access, Some(&duplicate_refresh)),
            None,
        )),
        "second authorization-code grant commit must fail",
    );
    assert_eq!(duplicate, AUTHORIZATION_CODE_GRANT_CODE_MISSING);
    assert!(
        verify_access_token(&token_store, &duplicate_access).is_none(),
        "failed duplicate commit must not write access token"
    );
    assert!(
        get_refresh_token(&token_store, &duplicate_refresh).is_none(),
        "failed duplicate commit must not write refresh token"
    );

    clear_redis_token_store_for_test(url);
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_authorization_code_grant_commit_rejects_payload_mismatch() -> StoreTestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let url = url.trim();
    clear_redis_token_store_for_test(url);

    let code_store = redis_auth_code_store_for_test(url);
    let token_store = redis_token_store_for_test(url);
    let suffix = aegaeon_crypto::rand::random_base64url(16);
    let mut code = make_test_code(
        Some(&format!("state-mismatch-{suffix}")),
        Some(&format!("nonce-mismatch-{suffix}")),
    );
    code.code = format!("code-mismatch-{suffix}");
    let expected_code_payload = must_ok!(
        serde_json::to_string(&code).map_err(|err| err.to_string()),
        "serialize expected authorization code",
    );
    let mut stored_code = code.clone();
    stored_code.user_id = format!("tampered-user-{suffix}");
    let code_str = must_ok!(
        code_store.store_code_typed(stored_code),
        "store mismatched authorization code"
    );

    let access = format!("access-mismatch-{suffix}");
    let refresh = format!("refresh-mismatch-{suffix}");
    let err = must_err!(
        token_store.store_issued_authorization_code_grant(AuthorizationCodeGrantCommit::new(
            code_store.clone(),
            code_str.clone(),
            expected_code_payload.clone(),
            make_access_token(&access),
            Some(make_refresh_token(&refresh)),
            make_bearer_meta(&access, Some(&refresh)),
            None,
        )),
        "authorization-code grant commit must reject payload mismatch",
    );
    assert!(
        err.contains("authorization code payload changed before grant commit"),
        "unexpected mismatch error: {err}"
    );
    assert!(
        must_ok!(code_store.try_get_code(&code_str), "authorization code lookup").is_some(),
        "mismatched authorization code must not be consumed"
    );
    assert!(
        verify_access_token(&token_store, &access).is_none(),
        "failed mismatch commit must not write access token"
    );
    assert!(
        get_refresh_token(&token_store, &refresh).is_none(),
        "failed mismatch commit must not write refresh token"
    );

    clear_redis_token_store_for_test(url);
    Ok(())
}
