use super::*;
use crate::authcode::types::{RefreshGrantRef, RefreshTargetContext};

fn store(redis: bool) -> TokenStore {
    if !redis {
        return TokenStore::new_process_local_for_tests();
    }
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").expect("Redis URL required");
    let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
        "refresh-grant-{}",
        uuid::Uuid::new_v4()
    ));
    TokenStore {
        backend: TokenStoreBackend::Redis(
            RedisTokenStoreBackend::new(&url, &namespace).expect("Redis store"),
        ),
    }
}

fn pair(parent: Option<&RefreshToken>, ttl: u64) -> (AccessToken, BearerTokenMeta) {
    let mut access = AccessToken::new("client".into(), "user".into(), Some("read".into()), ttl);
    access.refresh_grant = parent.and_then(|parent| parent.refresh_grant.clone());
    let mut meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        granted_scopes: vec!["read".into()],
        audience: "https://resource.example".into(),
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access
            .created_at
            .checked_add(Duration::from_secs(ttl))
            .expect("expiry"),
        refresh_parent: parent.map(|parent| parent.token.clone()),
    });
    meta.refresh_grant = access.refresh_grant.clone();
    (access, meta)
}

fn initial(store: &TokenStore, ttl: u64) -> (AccessToken, RefreshToken) {
    initial_with_expiry(store, ttl, Duration::from_secs(300))
}

fn initial_with_expiry(
    store: &TokenStore,
    ttl: u64,
    refresh_lifetime: Duration,
) -> (AccessToken, RefreshToken) {
    let mut refresh = RefreshToken::with_ttl(
        refresh_input(
            "client",
            "user",
            Some("read"),
            Some("https://resource.example"),
        ),
        300,
    );
    refresh.expires_at = SystemTime::now() + refresh_lifetime;
    refresh.target_context = Some(RefreshTargetContext {
        version: 1,
        audience: "https://resource.example".into(),
        token_issuer: None,
        oidc_issuer: None,
    });
    let (access, meta) = pair(Some(&refresh), ttl);
    let (id, parent) = store
        .store_issued_grant(access, Some(refresh), meta)
        .expect("initial grant");
    (
        store
            .try_verify_access_token(&id)
            .expect("lookup")
            .expect("access active"),
        store
            .try_get_refresh_token(&parent.expect("refresh id"))
            .expect("lookup")
            .expect("refresh active"),
    )
}

fn rotate(store: &TokenStore, previous: &RefreshToken, ttl: u64) -> (AccessToken, RefreshToken) {
    let mut prepared = store
        .prepare_refresh_rotation(&previous.token)
        .expect("prepare");
    let refresh = prepared.rotate();
    assert_eq!(
        refresh.expires_at, previous.expires_at,
        "rotation preserves exact absolute expiry"
    );
    let (access, meta) = pair(Some(&refresh), ttl);
    store
        .store_refreshed_grant(&previous.token, access.clone(), refresh.clone(), meta)
        .expect("rotation commit");
    (access, refresh)
}

fn family_cases(redis: bool) {
    for generation in [1, 2] {
        let store = store(redis);
        let (a1, r1) = initial(&store, 600);
        let (other, _) = initial(&store, 600);
        let (a2, r2) = rotate(&store, &r1, 900);
        let (a3, r3) = rotate(&store, &r2, 1200);
        let accesses = [a1, a2, a3];
        let refreshes = [r1, r2, r3];
        assert!(accesses.iter().all(|access| access.exchange_root.is_none()));
        for access in &accesses {
            assert!(store
                .try_verify_access_token(&access.token)
                .unwrap()
                .is_some());
        }
        assert_eq!(
            store
                .try_revoke_token_for_client(&refreshes[generation].token, Some("wrong-client"))
                .unwrap(),
            ClientBoundRevocationOutcome::OwnerMismatch
        );
        assert!(store
            .try_verify_access_token(&accesses[0].token)
            .unwrap()
            .is_some());
        assert_eq!(
            store
                .try_revoke_token_for_client(&refreshes[generation].token, Some("client"))
                .unwrap(),
            ClientBoundRevocationOutcome::Revoked
        );
        for access in &accesses {
            assert!(store
                .try_verify_access_token(&access.token)
                .unwrap()
                .is_none());
        }
        for refresh in &refreshes {
            assert!(store.try_is_refresh_revoked(&refresh.token).unwrap());
        }
        assert!(
            store
                .try_verify_access_token(&other.token)
                .unwrap()
                .is_some(),
            "another authorization of same owner survives"
        );
        store
            .try_revoke_token_for_client(&refreshes[generation].token, Some("client"))
            .unwrap();
    }
    let store = store(redis);
    let (a1, r1) = initial(&store, 600);
    let (a2, r2) = rotate(&store, &r1, 900);
    let (a3, r3) = rotate(&store, &r2, 1200);
    store
        .try_revoke_token_for_client(&a2.token, Some("client"))
        .unwrap();
    assert!(store.try_verify_access_token(&a1.token).unwrap().is_some());
    assert!(store.try_verify_access_token(&a2.token).unwrap().is_none());
    assert!(store.try_verify_access_token(&a3.token).unwrap().is_some());
    assert!(!store.try_is_refresh_revoked(&r3.token).unwrap());
    assert!(matches!(
        store.prepare_refresh_rotation(&r1.token),
        Err(RefreshRotationError::Reused)
    ));
    assert!(store.try_verify_access_token(&a1.token).unwrap().is_none());
    assert!(store.try_verify_access_token(&a3.token).unwrap().is_none());
    assert!(store.try_is_refresh_revoked(&r3.token).unwrap());
}

fn legacy_cases(redis: bool) {
    let store = store(redis);
    let legacy = RefreshToken::new(refresh_input(
        "client",
        "user",
        Some("read"),
        Some("https://resource.example"),
    ));
    store
        .try_replace_refresh_token_record(legacy.clone())
        .unwrap();
    let (dependent, meta) = pair(Some(&legacy), 600);
    store
        .try_replace_access_token_record(dependent.clone())
        .unwrap();
    store.try_replace_bearer_meta_record(meta.clone()).unwrap();
    assert!(store
        .try_verify_access_token(&dependent.token)
        .unwrap()
        .is_none());
    assert!(matches!(
        store.prepare_refresh_rotation(&legacy.token),
        Err(RefreshRotationError::Invalid)
    ));
    let (derived, derived_meta) = pair(Some(&legacy), 600);
    assert!(store
        .store_access_for_refresh_parent(derived, derived_meta)
        .is_err());
    assert!(store.try_snapshot().unwrap().refresh_grants.is_empty());
    let (independent, meta) = pair(None, 600);
    store
        .store_issued_grant(independent.clone(), None, meta.clone())
        .unwrap();
    assert!(store
        .try_verify_access_token(&independent.token)
        .unwrap()
        .is_some());
    let mut mismatched = meta;
    mismatched.refresh_grant = Some(RefreshGrantRef {
        version: 99,
        id: "unsupported".into(),
    });
    store.try_replace_bearer_meta_record(mismatched).unwrap();
    assert!(store
        .try_verify_access_token(&independent.token)
        .unwrap()
        .is_none());
}

#[test]
fn refresh_grant_family_revocation_memory() {
    family_cases(false);
}
#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_grant_family_revocation() {
    family_cases(true);
}
#[test]
fn refresh_grant_legacy_and_independent_memory() {
    legacy_cases(false);
}
#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_grant_legacy_and_independent() {
    legacy_cases(true);
}

fn retention_cases(redis: bool) {
    for revoked in [false, true] {
        let store = store(redis);
        let (a1, r1) = initial_with_expiry(&store, 4, Duration::from_millis(800));
        let (a2, r2) = rotate(&store, &r1, 8);
        let reference = r1.refresh_grant.as_ref().unwrap();
        let snapshot = store.try_snapshot().unwrap();
        let record = &snapshot.refresh_grants[&reference.id];
        assert!(record.retain_until >= a2.created_at + Duration::from_secs(8));
        let stale = store
            .try_with_state("stale snapshot", Clone::clone)
            .unwrap();
        if revoked {
            store
                .try_revoke_token_for_client(&r2.token, Some("client"))
                .unwrap();
            store
                .try_mutate_state("restore stale token snapshot", |state| {
                    *state = stale.clone()
                })
                .unwrap();
            assert!(
                store.try_verify_access_token(&a1.token).unwrap().is_none(),
                "snapshot cannot resurrect revoked grant"
            );
        }
        std::thread::sleep(Duration::from_millis(950));
        store.try_cleanup_expired().unwrap();
        let snapshot = store.try_snapshot().unwrap();
        assert!(snapshot.refresh_tokens.is_empty());
        assert!(
            snapshot.access_tokens.contains_key(&a1.token),
            "child outlives refresh and old indexes"
        );
        let retained = &snapshot.refresh_grants[&reference.id];
        assert_eq!(retained.revoked, revoked);
        assert!(retained.retain_until >= record.retain_until);
        assert_eq!(
            store.try_verify_access_token(&a1.token).unwrap().is_some(),
            !revoked
        );
        if !revoked {
            store.try_revoke_tokens_by_subject("user").unwrap();
            assert!(
                store.try_snapshot().unwrap().refresh_grants[&reference.id].revoked,
                "subject revocation covers access descendants after parent cleanup"
            );
        }
    }
}

fn corruption_cases(redis: bool) {
    for missing in [true, false] {
        let store = store(redis);
        let (access, refresh) = initial(&store, 600);
        let reference = refresh.refresh_grant.as_ref().unwrap();
        match &store.backend {
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "corrupt grant fixture").unwrap();
                if missing {
                    state.refresh_grants.remove(&reference.id);
                } else {
                    state.refresh_grants.get_mut(&reference.id).unwrap().version = 99;
                }
            }
            TokenStoreBackend::Redis(backend) => {
                let mut conn = backend.connection().unwrap();
                let key = backend
                    .keyspace_for_tests()
                    .refresh_grant_key(&reference.id);
                if missing {
                    redis::cmd("DEL")
                        .arg(key)
                        .query::<usize>(&mut conn)
                        .unwrap();
                } else {
                    redis::cmd("SET")
                        .arg(key)
                        .arg("{malformed")
                        .query::<()>(&mut conn)
                        .unwrap();
                }
            }
        }
        assert!(store
            .try_verify_access_token(&access.token)
            .unwrap()
            .is_none());
        assert!(store
            .try_get_refresh_token(&refresh.token)
            .unwrap()
            .is_none());
        assert!(store.prepare_refresh_rotation(&refresh.token).is_err());
        store.try_get_bearer_meta(&access.token).unwrap();
        assert!(
            store
                .try_verify_access_token(&access.token)
                .unwrap()
                .is_none(),
            "observation cannot recreate grant"
        );
    }
    let store = store(redis);
    let (_, refresh) = initial(&store, 600);
    let mut collision = refresh.clone();
    collision.token = uuid::Uuid::new_v4().to_string();
    let (access, meta) = pair(Some(&collision), 600);
    assert!(store
        .store_issued_grant(access.clone(), Some(collision.clone()), meta)
        .is_err());
    assert!(store.try_get_bearer_meta(&access.token).unwrap().is_none());
    assert!(store
        .try_get_refresh_token(&collision.token)
        .unwrap()
        .is_none());
    let mut overflowing = AccessToken::new(
        "client".into(),
        "user".into(),
        Some("read".into()),
        u64::MAX,
    );
    let (_, mut meta) = pair(None, 600);
    meta.token_id.clone_from(&overflowing.token);
    overflowing.created_at = SystemTime::now();
    let before = store.try_snapshot().unwrap().refresh_grants.len();
    let parent = RefreshToken::new(refresh_input(
        "client",
        "user",
        Some("read"),
        Some("https://resource.example"),
    ));
    meta.refresh_parent = Some(parent.token.clone());
    assert!(store
        .store_issued_grant(overflowing.clone(), Some(parent), meta)
        .is_err());
    assert_eq!(store.try_snapshot().unwrap().refresh_grants.len(), before);
    assert!(store
        .try_get_bearer_meta(&overflowing.token)
        .unwrap()
        .is_none());
}

#[test]
fn refresh_grant_retention_and_stale_snapshot_memory() {
    retention_cases(false);
}
#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_grant_retention_and_stale_snapshot() {
    retention_cases(true);
}
#[test]
fn refresh_grant_corruption_collision_overflow_memory() {
    corruption_cases(false);
}
#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_grant_corruption_collision_overflow() {
    corruption_cases(true);
}
fn backend(store: &TokenStore) -> &RedisTokenStoreBackend {
    let TokenStoreBackend::Redis(backend) = &store.backend else {
        panic!("Redis required")
    };
    backend
}

fn redis_connection() -> redis::Connection {
    redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL").unwrap())
        .unwrap()
        .get_connection()
        .unwrap()
}

fn expire_writer_lease(store: &TokenStore) {
    // Only this test's random namespace. Force the finite lease to expire while
    // the writer is paused after its Rust authority observation, before Lua.
    let key = backend(store).keyspace_for_tests().lock_key();
    let mut conn = redis_connection();
    let present: bool = redis::cmd("EXISTS").arg(&key).query(&mut conn).unwrap();
    if present {
        redis::cmd("PEXPIRE")
            .arg(&key)
            .arg(1)
            .query::<()>(&mut conn)
            .unwrap();
        thread::sleep(Duration::from_millis(5));
        assert!(!redis::cmd("EXISTS")
            .arg(key)
            .query::<bool>(&mut conn)
            .unwrap());
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_redis_paused_rotation_and_remint_cannot_outlive_revocation() {
    for rotation in [true, false] {
        let store = store(true);
        let (_, parent) = initial(&store, 600);
        let mut successor = parent.clone();
        if rotation {
            successor = successor.rotate();
        }
        let (access, meta) = pair(Some(&successor), 1200);
        let output = access.token.clone();
        let successor_id = successor.token.clone();
        let (reached, release) = backend(&store)
            .install_grant_pause_for_tests(parent.refresh_grant.as_ref().unwrap(), "commit");
        let worker_store = store.clone();
        let previous = parent.token.clone();
        let worker = thread::spawn(move || {
            if rotation {
                worker_store
                    .store_refreshed_grant(&previous, access, successor, meta)
                    .map(|_| ())
                    .map_err(|e| format!("{e:?}"))
            } else {
                worker_store
                    .store_access_for_refresh_parent(access, meta)
                    .map(|_| ())
            }
        });
        reached.recv_timeout(Duration::from_secs(10)).unwrap();
        expire_writer_lease(&store);
        store
            .try_revoke_token_for_client(&parent.token, Some("client"))
            .unwrap();
        release.send(()).unwrap();
        assert!(
            worker.join().unwrap().is_err(),
            "paused writer must reject after denial"
        );
        assert!(
            store.try_get_bearer_meta(&output).unwrap().is_none(),
            "no child publication"
        );
        assert!(store.try_verify_access_token(&output).unwrap().is_none());
        assert!(store
            .try_get_refresh_token(&successor_id)
            .unwrap()
            .is_none());
        assert!(store.snapshot().refresh_grants[&parent.refresh_grant.unwrap().id].revoked);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_redis_paused_snapshot_cannot_restore_active_decision() {
    let store = store(true);
    let (access, parent) = initial(&store, 600);
    let (reached, release) = backend(&store)
        .install_grant_pause_for_tests(parent.refresh_grant.as_ref().unwrap(), "snapshot");
    let worker_store = store.clone();
    let worker = thread::spawn(move || worker_store.try_mutate_state("stale snapshot", |_| ()));
    reached.recv_timeout(Duration::from_secs(10)).unwrap();
    expire_writer_lease(&store);
    store
        .try_revoke_token_for_client(&parent.token, Some("client"))
        .unwrap();
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(
        store.try_get_bearer_meta(&access.token).unwrap().is_some(),
        "stale physical snapshot really restored bytes"
    );
    assert!(store
        .try_verify_access_token(&access.token)
        .unwrap()
        .is_none());
    assert!(store
        .try_get_refresh_token(&parent.token)
        .unwrap()
        .is_none());
    assert!(store.snapshot().refresh_grants[&parent.refresh_grant.unwrap().id].revoked);
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_redis_cleanup_cas_preserves_concurrent_watermark_extension() {
    let store = store(true);
    let (_, parent) = initial(&store, 600);
    let reference = parent.refresh_grant.as_ref().unwrap();
    let old = store.snapshot().refresh_grants[&reference.id].retain_until;
    let (reached, release) = backend(&store).install_grant_pause_for_tests(reference, "cleanup");
    let worker_store = store.clone();
    // Synthetic future cutoff selects an otherwise live decision. The barrier
    // exercises the actual Redis exact-record removal CAS while a real remint
    // extends retention; this is not evidence of wall-clock expiry occurring.
    let worker = thread::spawn(move || {
        backend(&worker_store).cleanup_grants_at_for_tests(old + Duration::from_secs(1))
    });
    reached.recv_timeout(Duration::from_secs(10)).unwrap();
    let (access, meta) = pair(Some(&parent), 1200);
    store
        .store_access_for_refresh_parent(access.clone(), meta)
        .unwrap();
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    let current = store.snapshot().refresh_grants[&reference.id].clone();
    assert!(current.retain_until > old);
    assert!(store
        .try_verify_access_token(&access.token)
        .unwrap()
        .is_some());
    store
        .try_revoke_token_for_client(&parent.token, Some("client"))
        .unwrap();
    assert!(store
        .try_verify_access_token(&access.token)
        .unwrap()
        .is_none());
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_redis_denial_survives_missing_and_oversized_cleanup_indexes() {
    for oversized in [false, true] {
        let store = store(true);
        let (a1, r1) = initial(&store, 600);
        let (a2, r2) = rotate(&store, &r1, 900);
        let (a3, _) = rotate(&store, &r2, 1200);
        let key = backend(&store)
            .keyspace_for_tests()
            .refresh_children_key(&r2.token);
        let mut conn = redis_connection();
        let children = if oversized {
            (0..16385)
                .map(|i| format!("missing-{i}"))
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let raw =
            serde_json::json!({"refresh_token":r2.token, "access_tokens":children}).to_string();
        redis::cmd("SET")
            .arg(key)
            .arg(raw)
            .query::<()>(&mut conn)
            .unwrap();
        let outcome = store.try_revoke_token_for_client(&r2.token, Some("client"));
        assert_eq!(outcome.is_err(), oversized);
        for access in [&a1, &a2, &a3] {
            assert!(store
                .try_verify_access_token(&access.token)
                .unwrap()
                .is_none());
        }
        if oversized {
            assert!(
                store.try_get_bearer_meta(&a2.token).unwrap().is_some(),
                "cleanup failure leaves bytes but no authority"
            );
        }
        assert!(store.snapshot().refresh_grants[&r2.refresh_grant.unwrap().id].revoked);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_redis_cleanup_advances_past_malformed_and_orphan_entries() {
    let store = store(true);
    let (_, parent) = initial(&store, 600);
    let reference = parent.refresh_grant.as_ref().unwrap();
    let watermark = store.snapshot().refresh_grants[&reference.id].retain_until;
    let keys = backend(&store).keyspace_for_tests();
    let mut conn = redis_connection();
    let mut malformed = Vec::new();
    for _ in 0..300 {
        let id = RefreshGrantRef::new().id;
        redis::cmd("SET")
            .arg(keys.refresh_grant_key(&id))
            .arg("{")
            .query::<()>(&mut conn)
            .unwrap();
        redis::cmd("ZADD")
            .arg(keys.expiry_refresh_grant_key())
            .arg(0)
            .arg(&id)
            .query::<()>(&mut conn)
            .unwrap();
        malformed.push(id);
    }
    let orphan = RefreshGrantRef::new().id;
    redis::cmd("ZADD")
        .arg(keys.expiry_refresh_grant_key())
        .arg(1)
        .arg(&orphan)
        .query::<()>(&mut conn)
        .unwrap();
    for _ in 0..3 {
        backend(&store)
            .cleanup_grants_at_for_tests(watermark + Duration::from_secs(1))
            .unwrap();
    }
    assert!(
        !redis::cmd("EXISTS")
            .arg(keys.refresh_grant_key(&reference.id))
            .query::<bool>(&mut conn)
            .unwrap(),
        "later expired record is not starved"
    );
    assert!(redis::cmd("ZSCORE")
        .arg(keys.expiry_refresh_grant_key())
        .arg(orphan)
        .query::<Option<f64>>(&mut conn)
        .unwrap()
        .is_none());
    for id in malformed {
        assert_eq!(
            redis::cmd("GET")
                .arg(keys.refresh_grant_key(&id))
                .query::<String>(&mut conn)
                .unwrap(),
            "{",
            "unknown-retention bytes preserved"
        );
    }
}

fn reference_disagreements(redis: bool) {
    let store = store(redis);
    let (access, parent) = initial(&store, 600);
    let (_, other) = initial(&store, 600);
    let original = store.try_get_bearer_meta(&access.token).unwrap().unwrap();
    let mut beyond_retention = original.clone();
    beyond_retention.expires_at = SystemTime::now() + Duration::from_secs(3600);
    assert!(
        !store.try_bearer_grant_active(&beyond_retention).unwrap(),
        "observed snapshot cannot exceed current retained authority"
    );
    let mut wrong = original.clone();
    wrong.refresh_grant = other.refresh_grant.clone();
    store.try_replace_bearer_meta_record(wrong).unwrap();
    assert!(store
        .try_verify_access_token(&access.token)
        .unwrap()
        .is_none());
    let mut missing = original.clone();
    missing.refresh_grant = None;
    store.try_replace_bearer_meta_record(missing).unwrap();
    assert!(store
        .try_verify_access_token(&access.token)
        .unwrap()
        .is_none());
    store
        .try_replace_bearer_meta_record(original.clone())
        .unwrap();
    let mut substituted_parent = original;
    substituted_parent.refresh_parent = Some(other.token.clone());
    store
        .try_replace_bearer_meta_record(substituted_parent.clone())
        .unwrap();
    for retain in [false, true] {
        let mut policy = crate::policy::SecurityPolicy::default();
        policy.refresh.retain_refresh_chain = retain;
        let validator = crate::authcode::TokenValidator::with_policy(
            store.clone(),
            Arc::new(crate::kms::InMemoryKeyManager::new()),
            policy,
        );
        assert_eq!(
            validator
                .validate_refresh_parent(&substituted_parent)
                .is_ok(),
            !retain,
            "optional parent lookup must check its grant reference when enabled"
        );
    }
    for output_ref in [None, other.refresh_grant] {
        let mut successor = parent.clone().rotate();
        let (mut child, mut meta) = pair(Some(&successor), 900);
        child.refresh_grant = output_ref.clone();
        meta.refresh_grant = output_ref.clone();
        successor.refresh_grant = output_ref;
        let id = child.token.clone();
        assert!(store
            .store_refreshed_grant(&parent.token, child, successor, meta)
            .is_err());
        assert!(store.try_get_bearer_meta(&id).unwrap().is_none());
    }
}

#[test]
fn refresh_grant_reference_disagreements_memory() {
    reference_disagreements(false);
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_grant_reference_disagreements() {
    reference_disagreements(true);
}

fn shortened_retention_rejects_descendants(redis: bool) {
    let store = store(redis);
    let (_, parent) = initial(&store, 60);
    let reference = parent.refresh_grant.as_ref().unwrap();
    let mut record = store.snapshot().refresh_grants[&reference.id].clone();
    record.retain_until = SystemTime::now() + Duration::from_secs(120);
    assert!(record.retain_until < parent.expires_at);
    overwrite_refresh_grant_record(&store, &record);
    let (access, meta) = pair(Some(&parent), 900);
    let id = access.token.clone();
    assert!(store.store_access_for_refresh_parent(access, meta).is_err());
    assert!(store.try_get_bearer_meta(&id).unwrap().is_none());
    assert!(!store
        .try_set_refresh_sender_binding(
            &parent.token,
            Some(SenderBinding::DPoP {
                jkt: "short-retention".into()
            })
        )
        .unwrap());
    assert!(store.snapshot().refresh_tokens[&parent.token]
        .sender_binding
        .is_none());
    let successor = parent.clone().rotate();
    let (access, meta) = pair(Some(&successor), 900);
    let id = access.token.clone();
    assert!(store
        .store_refreshed_grant(&parent.token, access, successor, meta)
        .is_err());
    assert!(store.try_get_bearer_meta(&id).unwrap().is_none());
    assert!(!store.snapshot().refresh_tokens[&parent.token].rotated);
    assert_eq!(
        store.snapshot().refresh_grants[&reference.id].retain_until,
        record.retain_until,
        "inconsistent old retention is not repaired by remint, sender update or rotation"
    );
}

#[test]
fn refresh_grant_shortened_retention_rejects_descendants_memory() {
    shortened_retention_rejects_descendants(false);
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_grant_shortened_retention_rejects_descendants() {
    shortened_retention_rejects_descendants(true);
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn refresh_grant_redis_sender_update_rechecks_exact_parent_expiry() {
    let store = store(true);
    let (_, parent) = initial_with_expiry(&store, 600, Duration::from_millis(150));
    let (reached, release) = backend(&store)
        .install_grant_pause_for_tests(parent.refresh_grant.as_ref().unwrap(), "commit");
    let worker_store = store.clone();
    let id = parent.token.clone();
    let worker = thread::spawn(move || {
        worker_store.try_set_refresh_sender_binding(
            &id,
            Some(SenderBinding::DPoP {
                jkt: "fixture-jkt".into(),
            }),
        )
    });
    reached.recv_timeout(Duration::from_secs(5)).unwrap();
    thread::sleep(
        parent
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO)
            + Duration::from_millis(5),
    );
    expire_writer_lease(&store);
    release.send(()).unwrap();
    assert!(
        !worker.join().unwrap().unwrap(),
        "exact token deadline is checked after writer resumes"
    );
    assert!(store.snapshot().refresh_tokens[&parent.token]
        .sender_binding
        .is_none());
}
