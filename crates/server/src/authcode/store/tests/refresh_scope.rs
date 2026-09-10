use super::*;

fn scope_fixture(store: &TokenStore) -> Result<RefreshToken, String> {
    let suffix = aegaeon_crypto::rand::random_base64url(8);
    let mut previous = make_refresh_token(&format!("scope-rt-{suffix}"));
    previous.scope = Some("read write".to_string());
    let mut access = make_access_token(&format!("scope-at-{suffix}"));
    access.scope = previous.scope.clone();
    let mut meta = make_bearer_meta(&access.token, Some(&previous.token));
    meta.granted_scopes = vec!["read".to_string(), "write".to_string()];
    store.store_issued_grant(access, Some(previous.clone()), meta)?;
    Ok(previous)
}

fn replacement(
    previous: &RefreshToken,
    scope: &str,
) -> (AccessToken, RefreshToken, BearerTokenMeta) {
    let mut parent = previous.clone();
    let refresh = parent.rotate();
    let mut access = make_access_token(&format!("scope-at-{}", refresh.token));
    access.scope = Some(scope.to_string());
    let mut meta = make_bearer_meta(&access.token, Some(&refresh.token));
    meta.granted_scopes = scope.split(' ').map(str::to_owned).collect();
    (access, refresh, meta)
}

fn narrowing(store: &TokenStore) -> StoreTestResult {
    let previous = scope_fixture(store)?;
    let (access, refresh, meta) = replacement(&previous, "read");
    let (_, next) = store
        .store_refreshed_grant(&previous.token, access, refresh, meta)
        .map_err(|error| format!("AT-only narrowing must be accepted: {error:?}"))?;
    let saved = store
        .try_get_refresh_token(&next)?
        .ok_or("replacement missing")?;
    assert_eq!(saved.scope, previous.scope);
    let (access, refresh, meta) = replacement(&saved, "read write");
    store
        .store_refreshed_grant(&next, access, refresh, meta)
        .map_err(|error| format!("the original grant must remain available: {error:?}"))?;
    Ok(())
}

fn changed_replacement_rejected(store: &TokenStore) -> StoreTestResult {
    for scope in ["read", "read write admin"] {
        let previous = scope_fixture(store)?;
        let (access, mut refresh, meta) = replacement(&previous, scope);
        refresh.scope = Some(scope.to_string());
        let access_key = access.token.clone();
        let refresh_key = refresh.token.clone();
        assert!(
            matches!(
                store.store_refreshed_grant(&previous.token, access, refresh, meta),
                Err(RefreshRotationError::InconsistentGrant)
            ),
            "RT scope must not change to {scope}"
        );
        assert!(store.try_get_refresh_token(&refresh_key)?.is_none());
        assert!(store.try_get_bearer_meta(&access_key)?.is_none());
        assert!(
            !store
                .try_get_refresh_token(&previous.token)?
                .ok_or("previous missing")?
                .rotated
        );
        let (access, refresh, meta) = replacement(&previous, "read write");
        store
            .store_refreshed_grant(&previous.token, access, refresh, meta)
            .map_err(|error| format!("rejected write must leave grant usable: {error:?}"))?;
    }
    Ok(())
}

fn expansion_rejected(store: &TokenStore) -> StoreTestResult {
    let previous = scope_fixture(store)?;
    let (access, refresh, meta) = replacement(&previous, "read write admin");
    assert!(matches!(
        store.store_refreshed_grant(&previous.token, access, refresh, meta),
        Err(RefreshRotationError::InconsistentGrant)
    ));
    assert!(
        !store
            .try_get_refresh_token(&previous.token)?
            .ok_or("previous missing")?
            .rotated
    );
    Ok(())
}

#[test]
fn refresh_scope_store_allows_at_narrowing() -> StoreTestResult {
    narrowing(&TokenStore::new_process_local_for_tests())
}

#[test]
fn refresh_scope_store_rejects_changed_replacement() -> StoreTestResult {
    changed_replacement_rejected(&TokenStore::new_process_local_for_tests())
}

#[test]
fn refresh_scope_store_rejects_access_expansion() -> StoreTestResult {
    expansion_rejected(&TokenStore::new_process_local_for_tests())
}

#[test]
fn refresh_scope_store_initial_grant_still_requires_scope_equality() -> StoreTestResult {
    let store = TokenStore::new_process_local_for_tests();
    let mut refresh = make_refresh_token("initial-mismatch");
    refresh.scope = Some("read write".to_string());
    let access = make_access_token("initial-mismatch-at");
    let meta = make_bearer_meta(&access.token, Some(&refresh.token));
    assert!(store
        .store_issued_grant(access, Some(refresh), meta)
        .is_err());
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_scope_store_invariants() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|error| error.to_string())?;
    let store = redis_token_store_for_test(&url);
    narrowing(&store)?;
    changed_replacement_rejected(&store)?;
    expansion_rejected(&store)
}
