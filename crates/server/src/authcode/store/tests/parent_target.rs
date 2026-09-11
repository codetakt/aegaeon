use super::*;
use crate::authcode::types::RefreshTargetContext;
use uuid::Uuid;

fn parent(store: &TokenStore, target: &str) -> StoreTestResult {
    let mut refresh = make_refresh_token(&Uuid::new_v4().to_string());
    refresh.resource = None;
    refresh.target_context = Some(RefreshTargetContext {
        version: 1,
        audience: target.to_string(),
        token_issuer: Some("https://issuer.example".to_string()),
        oidc_issuer: Some("https://issuer.example".to_string()),
    });
    store.try_replace_refresh_token_record(refresh.clone())?;
    let access = make_access_token(&Uuid::new_v4().to_string());
    let mut meta = make_bearer_meta(&access.token, Some(&refresh.token));
    meta.audience = target.to_string();
    let key = access.token.clone();
    store.store_access_for_refresh_parent(access, meta)?;
    assert_eq!(
        store
            .try_get_bearer_meta(&key)?
            .ok_or("metadata missing")?
            .audience,
        target
    );
    assert!(
        !store
            .try_get_refresh_token(&refresh.token)?
            .ok_or("parent missing")?
            .rotated
    );
    Ok(())
}

fn wrong_fallback(store: &TokenStore) -> StoreTestResult {
    let mut refresh = make_refresh_token(&Uuid::new_v4().to_string());
    refresh.target_context = Some(RefreshTargetContext {
        version: 1,
        audience: "https://issuer.example/userinfo".to_string(),
        token_issuer: Some("https://issuer.example".to_string()),
        oidc_issuer: Some("https://issuer.example".to_string()),
    });
    store.try_replace_refresh_token_record(refresh.clone())?;
    let access = make_access_token(&Uuid::new_v4().to_string());
    let key = access.token.clone();
    let mut meta = make_bearer_meta(&key, Some(&refresh.token));
    meta.audience = refresh.client_id.clone();
    assert!(store
        .store_access_for_refresh_parent(access.clone(), meta.clone())
        .is_err());
    assert!(store.try_get_bearer_meta(&key)?.is_none());
    assert!(store.try_verify_access_token(&key)?.is_none());
    meta.audience = "https://issuer.example/userinfo".to_string();
    store.store_access_for_refresh_parent(access, meta)?;
    Ok(())
}

#[test]
fn refresh_parent_target_accepts_resolved_oidc_audience() -> StoreTestResult {
    parent(
        &TokenStore::new_process_local_for_tests(),
        "https://issuer.example/userinfo",
    )
}

#[test]
fn refresh_parent_target_rejects_client_fallback_without_writes() -> StoreTestResult {
    wrong_fallback(&TokenStore::new_process_local_for_tests())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_parent_target_preserved() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|error| error.to_string())?;
    let store = redis_token_store_for_test(&url);
    parent(&store, "https://issuer.example/userinfo")?;
    wrong_fallback(&store)
}
