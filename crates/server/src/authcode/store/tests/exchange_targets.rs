use super::*;
use crate::policy::token_exchange::TokenExchangePolicy;

fn exchange_policy() -> TokenExchangePolicy {
    serde_json::from_value(serde_json::json!({"version":1,
        "targets":[{"audience":"api","resourceAliases":[]}],
        "rules":[{"clientId":"test-client","sourceAudience":"test-client","targetAudience":"api",
            "scopes":[{"targetScope":"api.read","sourceScopes":["read"]}],"defaultScopes":["api.read"]}]
    })).expect("policy")
}

fn fixture(store: &TokenStore) -> Result<(RefreshToken, BearerTokenMeta), String> {
    fixture_with_access_ttl(store, 300)
}

fn fixture_with_access_ttl(
    store: &TokenStore,
    ttl: u64,
) -> Result<(RefreshToken, BearerTokenMeta), String> {
    let suffix = uuid::Uuid::new_v4();
    let mut refresh = make_refresh_token(&format!("exchange-rt-{suffix}"));
    refresh.exchange_grant = exchange_policy().capture(
        "issuer",
        &refresh.client_id,
        &refresh.user_id,
        &refresh.client_id,
        &["read".into()],
        &["api.read".into()],
    );
    refresh.exchange_grant = refresh
        .exchange_grant
        .map(|grant| grant.with_lineage_deadline(SystemTime::now() + Duration::from_secs(900)));
    let mut access = make_access_token(&format!("exchange-at-{suffix}"));
    access.expires_in = ttl;
    access.exchange_root = refresh
        .exchange_grant
        .as_ref()
        .and_then(|grant| grant.root())
        .cloned();
    let mut meta = make_bearer_meta(&access.token, Some(&refresh.token));
    meta.exchange_grant = refresh.exchange_grant.clone();
    meta.issued_at = access.created_at;
    meta.expires_at = access.created_at + Duration::from_secs(access.expires_in);
    store.store_issued_grant(access, Some(refresh.clone()), meta.clone())?;
    Ok((
        store
            .try_get_refresh_token(&refresh.token)?
            .ok_or("refresh missing")?,
        store
            .try_get_bearer_meta(&meta.token_id)?
            .ok_or("metadata missing")?,
    ))
}

fn output(subject: &BearerTokenMeta) -> (AccessToken, BearerTokenMeta) {
    let p = exchange_policy();
    let (scopes, grant) = p
        .authorize(
            subject.exchange_grant.as_ref().expect("subject grant"),
            "issuer",
            &subject.client_id,
            &subject.user_id,
            &subject.audience,
            &subject.granted_scopes,
            "api",
            None,
        )
        .expect("authorized");
    let mut access = make_access_token(&format!("exchanged-{}", uuid::Uuid::new_v4()));
    access.scope = Some(scopes.join(" "));
    access.expires_in = 120;
    let mut meta = make_bearer_meta(&access.token, subject.refresh_parent.as_deref());
    access.refresh_grant = subject.refresh_grant.clone();
    meta.refresh_grant = subject.refresh_grant.clone();
    meta.audience = "api".into();
    meta.granted_scopes = scopes;
    access.exchange_root = grant.root().cloned();
    meta.exchange_grant = Some(grant);
    meta.issued_at = access.created_at;
    meta.expires_at = access.created_at + Duration::from_secs(access.expires_in);
    (access, meta)
}

fn scenarios(store: &TokenStore) -> StoreTestResult {
    let (refresh, subject) = fixture(store)?;
    let (access, meta) = output(&subject);
    let token = store.store_exchanged_access(access, meta.clone(), subject.clone())?;
    assert_eq!(
        store
            .try_get_bearer_meta(&token)?
            .ok_or("metadata missing")?
            .audience,
        "api"
    );
    assert!(
        store.try_verify_access_token(&subject.token_id)?.is_some(),
        "exchange must not consume subject"
    );
    for kind in 0..6 {
        let (mut access, mut bad) = output(&subject);
        match kind {
            0 => bad.exchange_grant = None,
            1 => {
                bad.audience = "other".into();
            }
            2 => {
                access.scope = Some("api.write".into());
                bad.granted_scopes = vec!["api.write".into()];
            }
            3 => {
                bad.user_id = "other".into();
                access.user_id = "other".into();
            }
            4 => {
                bad.expires_at = subject.expires_at + Duration::from_secs(1);
            }
            _ => bad.authorization_details = Some(serde_json::json!([{"type":"payment"}])),
        }
        let id = access.token.clone();
        assert!(
            store
                .store_exchanged_access(access, bad, subject.clone())
                .is_err(),
            "case {kind}"
        );
        assert!(
            store.try_verify_access_token(&id)?.is_none(),
            "rejection leaves no output"
        );
    }
    store.try_revoke_token_for_client(&refresh.token, Some(&refresh.client_id))?;
    assert!(
        store.try_verify_access_token(&token)?.is_none(),
        "root revocation must invalidate already-issued output"
    );
    let (access, meta) = output(&subject);
    assert!(
        store.store_exchanged_access(access, meta, subject).is_err(),
        "revoke before commit must reject"
    );

    let (refresh, subject) = fixture(store)?;
    let mut rotating = refresh.clone();
    let next = rotating.rotate();
    let mut access = make_access_token(&format!("rotate-{}", next.token));
    access.exchange_root = next
        .exchange_grant
        .as_ref()
        .and_then(|grant| grant.root())
        .cloned();
    let mut meta = make_bearer_meta(&access.token, Some(&next.token));
    access.refresh_grant = next.refresh_grant.clone();
    meta.refresh_grant = next.refresh_grant.clone();
    meta.exchange_grant = next.exchange_grant.clone();
    store
        .store_refreshed_grant(&refresh.token, access, next, meta)
        .map_err(|e| format!("rotate: {e:?}"))?;
    let (access, meta) = output(&subject);
    assert!(
        store.store_exchanged_access(access, meta, subject).is_err(),
        "rotation before commit must reject"
    );
    Ok(())
}

#[test]
fn token_exchange_target_commit_preserves_authority_and_revocation() -> StoreTestResult {
    scenarios(&TokenStore::new_process_local_for_tests())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn token_exchange_target_redis_commit_preserves_authority_and_revocation() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    scenarios(&redis_token_store_for_test(&url))
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn token_exchange_target_redis_races_with_revocation() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    let store = redis_token_store_for_test(&url);
    for _ in 0..20 {
        let (refresh, subject) = fixture(&store)?;
        let (access, meta) = output(&subject);
        let id = access.token.clone();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let worker_store = store.clone();
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            worker_store.store_exchanged_access(access, meta, subject)
        });
        barrier.wait();
        store.try_revoke_token_for_client(&refresh.token, Some(&refresh.client_id))?;
        let _outcome = worker.join().map_err(|_| "exchange worker panicked")?;
        assert!(
            store.try_verify_access_token(&id)?.is_none(),
            "after revocation no output may remain usable"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn token_exchange_target_redis_revocation_survives_lost_child_index() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    let store = redis_token_store_for_test(&url);
    let (refresh, subject) = fixture(&store)?;
    let (access, meta) = output(&subject);
    let id = store.store_exchanged_access(access, meta, subject)?;
    // Reproduce the state after a lease-expired older writer overwrites children.
    let mut conn = redis::Client::open(url)
        .map_err(|e| e.to_string())?
        .get_connection()
        .map_err(|e| e.to_string())?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("*refresh-children*")
        .query(&mut conn)
        .map_err(|e| e.to_string())?;
    let mut changed = 0;
    for key in keys {
        let raw: String = redis::cmd("GET")
            .arg(&key)
            .query(&mut conn)
            .map_err(|e| e.to_string())?;
        let mut value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if value["refresh_token"] == refresh.token {
            changed += 1;
            value["access_tokens"] = serde_json::json!([]);
            redis::cmd("SET")
                .arg(key)
                .arg(value.to_string())
                .query::<()>(&mut conn)
                .map_err(|e| e.to_string())?;
        }
    }
    assert_eq!(changed, 1, "must corrupt the selected root index");
    store.try_revoke_token_for_client(&refresh.token, Some(&refresh.client_id))?;
    assert!(
        store.try_verify_access_token(&id)?.is_none(),
        "orphaned exchange output must be revoked"
    );
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn token_exchange_target_redis_root_denial_precedes_cleanup_budget() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    let store = redis_token_store_for_test(&url);
    let (refresh, subject) = fixture(&store)?;
    let (access, meta) = output(&subject);
    let id = store.store_exchanged_access(access, meta, subject.clone())?;
    let mut conn = redis::Client::open(url)
        .map_err(|e| e.to_string())?
        .get_connection()
        .map_err(|e| e.to_string())?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("*refresh-children*")
        .query(&mut conn)
        .map_err(|e| e.to_string())?;
    let mut changed = 0;
    for key in keys {
        let raw: String = redis::cmd("GET")
            .arg(&key)
            .query(&mut conn)
            .map_err(|e| e.to_string())?;
        let mut value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if value["refresh_token"] == refresh.token {
            changed += 1;
            value["access_tokens"] = serde_json::json!((0..16385)
                .map(|i| format!("budget-child-{i}"))
                .collect::<Vec<_>>());
            redis::cmd("SET")
                .arg(key)
                .arg(value.to_string())
                .query::<()>(&mut conn)
                .map_err(|e| e.to_string())?;
        }
    }
    assert_eq!(changed, 1);
    assert!(
        store
            .try_revoke_token_for_client(&refresh.token, Some(&refresh.client_id))
            .is_err(),
        "cleanup budget must really fail"
    );
    assert!(
        store.try_get_bearer_meta(&id)?.is_some(),
        "record survives failed cleanup"
    );
    assert!(
        store.try_verify_access_token(&id)?.is_none(),
        "root denial is independent of cleanup success"
    );
    assert!(
        store.try_get_refresh_token(&refresh.token)?.is_none(),
        "same root refresh must be unusable"
    );
    assert!(
        store
            .try_list_bearer_meta_for_subject(&subject.user_id)?
            .iter()
            .all(|meta| meta.token_id != id && meta.token_id != subject.token_id),
        "active management inventory must exclude a denied root"
    );
    assert!(
        store
            .try_list_refresh_tokens_for_subject(&subject.user_id)?
            .iter()
            .all(|token| token.token != refresh.token),
        "active refresh inventory must exclude a denied root"
    );
    let (access, meta) = output(&subject);
    assert!(
        store.store_exchanged_access(access, meta, subject).is_err(),
        "publication after denial must fail"
    );
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_redis_paused_exchange_rejects_revoked_ordinary_authority() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
        "grant-exchange-race-{}",
        uuid::Uuid::new_v4()
    ));
    let backend = RedisTokenStoreBackend::new(&url, &namespace).map_err(|e| e.to_string())?;
    let store = TokenStore {
        backend: TokenStoreBackend::Redis(backend.clone()),
    };
    let (parent, subject) = fixture(&store)?;
    let (access, meta) = output(&subject);
    let id = access.token.clone();
    let (reached, release) =
        backend.install_grant_pause_for_tests(parent.refresh_grant.as_ref().unwrap(), "commit");
    let worker_store = store.clone();
    let worker = thread::spawn(move || worker_store.store_exchanged_access(access, meta, subject));
    reached
        .recv_timeout(Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    let mut conn = redis::Client::open(url)
        .and_then(|c| c.get_connection())
        .map_err(|e| e.to_string())?;
    redis::cmd("PEXPIRE")
        .arg(backend.keyspace_for_tests().lock_key())
        .arg(1)
        .query::<()>(&mut conn)
        .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(5));
    store.try_revoke_token_for_client(&parent.token, Some("test-client"))?;
    release.send(()).map_err(|e| e.to_string())?;
    assert!(worker.join().map_err(|_| "exchange worker panic")?.is_err());
    assert!(store.try_get_bearer_meta(&id)?.is_none());
    assert!(store.try_verify_access_token(&id)?.is_none());
    assert!(store.snapshot().refresh_grants[&parent.refresh_grant.unwrap().id].revoked);
    Ok(())
}

fn remint_keeps_exchange_authority(store: &TokenStore) -> StoreTestResult {
    let (parent, subject) = fixture(store)?;
    let mut access = make_access_token(&format!("remint-{}", uuid::Uuid::new_v4()));
    access.refresh_grant = parent.refresh_grant.clone();
    access.exchange_root = parent
        .exchange_grant
        .as_ref()
        .and_then(|grant| grant.root())
        .cloned();
    let mut meta = subject.clone();
    meta.token_id = access.token.clone();
    meta.issued_at = access.created_at;
    meta.expires_at = access.created_at + Duration::from_secs(access.expires_in);
    store.store_access_for_refresh_parent(access.clone(), meta.clone())?;
    assert!(store.try_verify_access_token(&access.token)?.is_some());
    access.token = format!("remint-stripped-{}", uuid::Uuid::new_v4());
    access.exchange_root = None;
    meta.token_id = access.token.clone();
    meta.exchange_grant = None;
    assert!(
        store
            .store_access_for_refresh_parent(access.clone(), meta)
            .is_err(),
        "remint cannot strip inherited exchange authority"
    );
    assert!(store.try_get_bearer_meta(&access.token)?.is_none());
    Ok(())
}

#[test]
fn refresh_grant_remint_preserves_exchange_authority_memory() -> StoreTestResult {
    remint_keeps_exchange_authority(&TokenStore::new_process_local_for_tests())
}
#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_remint_preserves_exchange_authority_redis() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    remint_keeps_exchange_authority(&redis_token_store_for_test(&url))
}

fn exchange_rejects_shortened_parent_retention(store: &TokenStore) -> StoreTestResult {
    let (parent, subject) = fixture_with_access_ttl(store, 180)?;
    let (access, meta) = output(&subject);
    store.store_exchanged_access(access, meta, subject.clone())?;
    let reference = parent.refresh_grant.as_ref().unwrap();
    let mut record = store.snapshot().refresh_grants[&reference.id].clone();
    record.retain_until = subject.expires_at + Duration::from_secs(30);
    assert!(subject.expires_at < record.retain_until && record.retain_until < parent.expires_at);
    overwrite_refresh_grant_record(store, &record);
    assert!(
        store.try_verify_access_token(&subject.token_id)?.is_some(),
        "subject fits retained watermark"
    );
    let (access, meta) = output(&subject);
    let id = access.token.clone();
    assert!(
        store.store_exchanged_access(access, meta, subject).is_err(),
        "consulted parent must fit existing watermark"
    );
    assert!(store.try_get_bearer_meta(&id)?.is_none());
    assert_eq!(
        store.snapshot().refresh_grants[&reference.id].retain_until,
        record.retain_until
    );
    Ok(())
}

#[test]
fn refresh_grant_exchange_rejects_shortened_parent_retention_memory() -> StoreTestResult {
    exchange_rejects_shortened_parent_retention(&TokenStore::new_process_local_for_tests())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_exchange_rejects_shortened_parent_retention_redis() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    exchange_rejects_shortened_parent_retention(&redis_token_store_for_test(&url))
}
