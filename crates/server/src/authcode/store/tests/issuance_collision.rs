#[test]
fn store_issued_grant_rejects_token_key_collision() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    must_ok!(
        store.store_issued_grant(
            make_access_token("issued-collision-access"),
            Some(make_refresh_token("issued-collision-refresh")),
            make_bearer_meta("issued-collision-access", Some("issued-collision-refresh")),
        ),
        "initial issued grant should be stored",
    );

    let err = must_err!(
        store.store_issued_grant(
            make_access_token("issued-collision-access"),
            None,
            make_bearer_meta("issued-collision-access", None),
        ),
        "issued grant token collision must fail closed",
    );

    assert!(
        err.contains("token key collision"),
        "unexpected collision error: {err}"
    );
    Ok(())
}

#[test]
fn authorization_code_grant_commit_rejects_payload_mismatch_without_consuming_code(
) -> StoreTestResult {
    let code_store = AuthCodeStore::new_process_local_for_tests();
    let token_store = TokenStore::new_process_local_for_tests();
    let suffix = uuid::Uuid::new_v4();
    let mut code = make_test_code(
        Some(&format!("state-in-memory-mismatch-{suffix}")),
        Some(&format!("nonce-in-memory-mismatch-{suffix}")),
    );
    code.code = format!("code-in-memory-mismatch-{suffix}");
    let expected_payload = must_ok!(
        serde_json::to_string(&code).map_err(|err| err.to_string()),
        "serialize expected authorization code",
    );
    let mut stored_code = code;
    stored_code.user_id = format!("tampered-user-{suffix}");
    let code_str = must_ok!(
        code_store.store_code_typed(stored_code),
        "store mismatched authorization code",
    );

    let access = format!("access-in-memory-mismatch-{suffix}");
    let refresh = format!("refresh-in-memory-mismatch-{suffix}");
    let err = must_err!(
        token_store.store_issued_authorization_code_grant(AuthorizationCodeGrantCommit::new(
            code_store.clone(),
            code_str.clone(),
            expected_payload.clone(),
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
    assert!(
        get_bearer_meta(&token_store, &access).is_none(),
        "failed mismatch commit must not write bearer metadata"
    );
    Ok(())
}

#[test]
fn store_access_for_refresh_parent_rejects_token_key_collision() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let refresh_parent = store_refresh_token(&store, make_refresh_token("refresh-parent-collision"));
    must_ok!(
        store.store_access_for_refresh_parent(
            make_access_token("refresh-parent-collision-access"),
            make_bearer_meta(
                "refresh-parent-collision-access",
                Some(&refresh_parent),
            ),
        ),
        "initial refresh-parent access token should be stored",
    );

    let err = must_err!(
        store.store_access_for_refresh_parent(
            make_access_token("refresh-parent-collision-access"),
            make_bearer_meta(
                "refresh-parent-collision-access",
                Some(&refresh_parent),
            ),
        ),
        "refresh-parent token collision must fail closed",
    );

    assert!(
        err.contains("token key collision"),
        "unexpected collision error: {err}"
    );
    Ok(())
}
