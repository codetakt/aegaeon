use super::*;
use crate::policy::token_exchange::TokenExchangePolicy;

fn fixture() -> (TokenStore, redis::Connection) {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").expect("dedicated Redis URL");
    fixture_at(&url)
}

fn fixture_at(url: &str) -> (TokenStore, redis::Connection) {
    let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
        "inventory-time-{}",
        uuid::Uuid::new_v4()
    ));
    let store = TokenStore {
        backend: TokenStoreBackend::Redis(RedisTokenStoreBackend::new(url, &namespace).unwrap()),
    };
    let observer = redis::Client::open(url).unwrap().get_connection().unwrap();
    (store, observer)
}

fn connection_count(conn: &mut redis::Connection) -> u64 {
    let info: String = redis::cmd("INFO").arg("stats").query(conn).unwrap();
    info.lines()
        .find_map(|line| line.strip_prefix("total_connections_received:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "requires a dedicated AEGAEON_TEST_REDIS_URL; no concurrent clients"]
fn redis_inventory_connections_remain_constant() {
    use std::net::ToSocketAddrs;

    // Count transaction connections to one endpoint. redis-rs races DNS
    // addresses during setup, so localhost's IPv4/IPv6 sockets can both be
    // accepted even though only one executes commands. Other fixtures retain
    // the supplied hostname, including its TLS identity.
    let mut url = url::Url::parse(&std::env::var("AEGAEON_TEST_REDIS_URL").unwrap()).unwrap();
    assert_eq!(
        url.scheme(),
        "redis",
        "connection-count fixture requires plaintext Redis"
    );
    let address = (url.host_str().unwrap(), url.port().unwrap_or(6379))
        .to_socket_addrs()
        .unwrap()
        .next()
        .expect("fixture endpoint");
    url.set_ip_host(address.ip()).unwrap();
    let mut observations = Vec::new();
    for count in [1, 8] {
        let (store, mut observer) = fixture_at(url.as_str());
        for _ in 0..count {
            issue_access_fixture(&store, make_access_token(&uuid::Uuid::new_v4().to_string()));
        }
        let before = connection_count(&mut observer);
        let listed = store.try_list_bearer_meta_for_subject("user").unwrap();
        let after = connection_count(&mut observer);
        assert_eq!(listed.len(), count);
        observations.push((count, after - before));
    }
    eprintln!("inventory item/connection counts: {observations:?}");
    assert_eq!(observations, vec![(1, 1), (8, 1)]);
}

fn redis_time(conn: &mut redis::Connection) -> (u64, u32) {
    redis::cmd("TIME").query(conn).unwrap()
}

fn redis_system_time(value: (u64, u32)) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::new(value.0, value.1 * 1000)
}

fn fractional_grant(store: &TokenStore, deadline: SystemTime) -> (RefreshToken, BearerTokenMeta) {
    let policy: TokenExchangePolicy = serde_json::from_value(serde_json::json!({"version":1,
        "targets":[{"audience":"api","resourceAliases":[]}],
        "rules":[{"clientId":"test-client","sourceAudience":"test-client","targetAudience":"api",
            "scopes":[{"targetScope":"api.read","sourceScopes":["read"]}],"defaultScopes":["api.read"]}]
    })).unwrap();
    let mut refresh = make_refresh_token(&uuid::Uuid::new_v4().to_string());
    refresh.expires_at = deadline;
    refresh.exchange_grant = policy
        .capture(
            "issuer",
            "test-client",
            "user",
            "test-client",
            &["read".into()],
            &["api.read".into()],
        )
        .map(|grant| grant.with_lineage_deadline(deadline));
    let mut access = make_access_token(&uuid::Uuid::new_v4().to_string());
    access.created_at = deadline - Duration::from_secs(1);
    access.expires_in = 1;
    access.exchange_root = refresh
        .exchange_grant
        .as_ref()
        .and_then(|grant| grant.root())
        .cloned();
    let mut meta = make_bearer_meta(&access.token, Some(&refresh.token));
    meta.exchange_grant = refresh.exchange_grant.clone();
    meta.issued_at = access.created_at;
    meta.expires_at = deadline;
    store
        .store_issued_grant(access, Some(refresh.clone()), meta.clone())
        .unwrap();
    let refresh = store
        .try_get_refresh_token(&refresh.token)
        .unwrap()
        .unwrap();
    let meta = store.try_get_bearer_meta(&meta.token_id).unwrap().unwrap();
    (refresh, meta)
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_rotation_preserves_live_fractional_root_deadline() {
    let (store, mut observer) = fixture();
    for attempt in 0..4 {
        let mut before = redis_time(&mut observer);
        if before.1 > 200_000 {
            thread::sleep(Duration::from_micros(u64::from(1_020_000 - before.1)));
            before = redis_time(&mut observer);
        }
        let deadline = SystemTime::UNIX_EPOCH + Duration::new(before.0, 950_000_000);
        let (mut previous, meta) = fractional_grant(&store, deadline);
        let next = previous.rotate();
        let mut access = make_access_token(&uuid::Uuid::new_v4().to_string());
        access.created_at = deadline - Duration::from_secs(1);
        access.expires_in = 1;
        access.refresh_grant = next.refresh_grant.clone();
        access.exchange_root = next
            .exchange_grant
            .as_ref()
            .and_then(|grant| grant.root())
            .cloned();
        let next_meta = BearerTokenMeta {
            token_id: access.token.clone(),
            refresh_parent: Some(next.token.clone()),
            ..meta
        };
        let commit_before = redis_time(&mut observer);
        let result = store.store_refreshed_grant(&previous.token, access, next.clone(), next_meta);
        let after = redis_time(&mut observer);
        eprintln!("fractional root attempt={attempt} before={commit_before:?} after={after:?} deadline={deadline:?} result={result:?}");
        if redis_system_time(after) >= deadline {
            continue;
        }
        assert_eq!(commit_before.0, before.0, "exercise the fractional second");
        assert!(
            result.is_ok(),
            "live fractional root must permit rotation: {result:?}"
        );
        assert!(store.try_get_refresh_token(&next.token).unwrap().is_some());
        return;
    }
    panic!("could not observe a bounded fractional commit; no passing timing inference");
}

fn backend(store: &TokenStore) -> &RedisTokenStoreBackend {
    match &store.backend {
        TokenStoreBackend::Redis(backend) => backend,
        _ => panic!("Redis fixture required"),
    }
}

fn raw(conn: &mut redis::Connection, key: &str) -> Option<String> {
    redis::cmd("GET").arg(key).query(conn).unwrap()
}

fn member(conn: &mut redis::Connection, key: &str, token: &str) -> bool {
    redis::cmd("SISMEMBER")
        .arg(key)
        .arg(token)
        .query(conn)
        .unwrap()
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_inventory_stale_observations_preserve_new_issuance_and_membership() {
    let (store, mut conn) = fixture();
    let refresh = make_refresh_token("refresh");
    let access = make_access_token("access");
    let meta = make_bearer_meta("access", Some("refresh"));
    store
        .store_issued_grant(access, Some(refresh), meta)
        .unwrap();
    let backend = backend(&store);
    let keys = backend.keyspace_for_tests();
    let access_key = keys.access_key("access");
    let access_before = raw(&mut conn, &access_key);
    for (record_key, subject_key, token) in [
        (
            keys.bearer_key("access"),
            keys.subject_bearer_key("user"),
            "access",
        ),
        (
            keys.refresh_key("refresh"),
            keys.subject_refresh_key("user"),
            "refresh",
        ),
    ] {
        let before = raw(&mut conn, &record_key).unwrap();
        for stale in [None, Some("old expired payload")] {
            backend.prune_inventory_observation_for_tests(&record_key, &subject_key, token, stale);
            assert_eq!(
                raw(&mut conn, &record_key).as_deref(),
                Some(before.as_str())
            );
            assert!(member(&mut conn, &subject_key, token));
            assert_eq!(raw(&mut conn, &access_key), access_before);
            assert!(store.try_verify_access_token("access").unwrap().is_some());
        }
        // An unchanged observed record permits pruning only this membership.
        backend.prune_inventory_observation_for_tests(
            &record_key,
            &subject_key,
            token,
            Some(&before),
        );
        assert!(!member(&mut conn, &subject_key, token));
        assert_eq!(
            raw(&mut conn, &record_key).as_deref(),
            Some(before.as_str())
        );
        redis::cmd("SADD")
            .arg(&subject_key)
            .arg("orphan")
            .query::<()>(&mut conn)
            .unwrap();
        backend.prune_inventory_observation_for_tests(
            "absent-inventory-record",
            &subject_key,
            "orphan",
            None,
        );
        assert!(!member(&mut conn, &subject_key, "orphan"));
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_inventory_filters_stale_records_without_deleting_authority() {
    for kind in ["expired", "owner", "identity", "malformed"] {
        let (store, mut conn) = fixture();
        let deadline = SystemTime::now() + Duration::from_secs(300);
        let (refresh, meta) = fractional_grant(&store, deadline);
        let keys = backend(&store).keyspace_for_tests();
        for (record_key, subject_key, token, field) in [
            (
                keys.bearer_key(&meta.token_id),
                keys.subject_bearer_key("user"),
                meta.token_id.as_str(),
                "token_id",
            ),
            (
                keys.refresh_key(&refresh.token),
                keys.subject_refresh_key("user"),
                refresh.token.as_str(),
                "token",
            ),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(&raw(&mut conn, &record_key).unwrap()).unwrap();
            match kind {
                "expired" => {
                    value["expires_at"] = serde_json::to_value(SystemTime::UNIX_EPOCH).unwrap()
                }
                "owner" => value["user_id"] = "other-user".into(),
                "identity" => value[field] = "other-token".into(),
                "malformed" => {}
                _ => unreachable!(),
            }
            let stored = if kind == "malformed" {
                "{".into()
            } else {
                value.to_string()
            };
            redis::cmd("SET")
                .arg(&record_key)
                .arg(&stored)
                .query::<()>(&mut conn)
                .unwrap();
            if field == "token_id" {
                let result = store.try_list_bearer_meta_for_subject("user");
                if kind == "malformed" {
                    assert!(result.is_err());
                } else {
                    assert!(result.unwrap().is_empty());
                }
            } else {
                let result = store.try_list_refresh_tokens_for_subject("user");
                if kind == "malformed" {
                    assert!(result.is_err());
                } else {
                    assert!(result.unwrap().is_empty());
                }
            }
            assert_eq!(
                raw(&mut conn, &record_key).as_deref(),
                Some(stored.as_str())
            );
            assert_eq!(member(&mut conn, &subject_key, token), kind == "malformed");
        }
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_inventory_preserves_grant_and_listed_access_validation() {
    for kind in [
        "missing",
        "revoked",
        "mismatch",
        "access-identity",
        "access-root",
        "meta-root",
        "root-revoked",
    ] {
        let (store, mut conn) = fixture();
        let (refresh, meta) =
            fractional_grant(&store, SystemTime::now() + Duration::from_secs(300));
        assert_eq!(
            store
                .try_list_bearer_meta_for_subject("user")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .try_list_refresh_tokens_for_subject("user")
                .unwrap()
                .len(),
            1
        );
        let keys = backend(&store).keyspace_for_tests();
        let grant_key = keys.refresh_grant_key(&refresh.refresh_grant.as_ref().unwrap().id);
        let access_key = keys.access_key(&meta.token_id);
        let meta_key = keys.bearer_key(&meta.token_id);
        if kind == "missing" {
            redis::cmd("DEL")
                .arg(&grant_key)
                .query::<()>(&mut conn)
                .unwrap();
        } else if kind == "root-revoked" {
            let root = refresh.exchange_grant.as_ref().unwrap().root().unwrap();
            redis::cmd("SET")
                .arg(keys.revoked_key(&root.id))
                .arg(
                    serde_json::json!({"token": root.id, "expires_at": root.expires_at})
                        .to_string(),
                )
                .query::<()>(&mut conn)
                .unwrap();
        } else {
            let key = match kind {
                "access-identity" | "access-root" => &access_key,
                "meta-root" => &meta_key,
                _ => &grant_key,
            };
            let mut value: serde_json::Value =
                serde_json::from_str(&raw(&mut conn, key).unwrap()).unwrap();
            match kind {
                "revoked" => value["revoked"] = true.into(),
                "mismatch" => value["user_id"] = "other-user".into(),
                "access-identity" => value["token"] = "other-token".into(),
                "access-root" => value["exchange_root"] = serde_json::Value::Null,
                "meta-root" => value["exchange_grant"] = serde_json::Value::Null,
                _ => unreachable!(),
            }
            redis::cmd("SET")
                .arg(key)
                .arg(value.to_string())
                .query::<()>(&mut conn)
                .unwrap();
        }
        let access_before = raw(&mut conn, &access_key);
        let meta_before = raw(&mut conn, &meta_key);
        assert!(
            store
                .try_list_bearer_meta_for_subject("user")
                .unwrap()
                .is_empty(),
            "{kind}"
        );
        if matches!(kind, "missing" | "revoked" | "mismatch" | "root-revoked") {
            assert!(
                store
                    .try_list_refresh_tokens_for_subject("user")
                    .unwrap()
                    .is_empty(),
                "{kind}"
            );
        }
        assert_eq!(raw(&mut conn, &access_key), access_before);
        assert_eq!(raw(&mut conn, &meta_key), meta_before);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_subject_missing_observation_preserves_new_issuance() {
    let (store, mut conn) = fixture();
    let keys = backend(&store).keyspace_for_tests();
    let cases = [
        (
            keys.access_key("access"),
            keys.subject_access_key("user"),
            "access",
        ),
        (
            keys.refresh_key("refresh"),
            keys.subject_refresh_key("user"),
            "refresh",
        ),
        (
            keys.bearer_key("access"),
            keys.subject_bearer_key("user"),
            "access",
        ),
    ];
    // Freeze the missing observations, then publish before stale pruning runs.
    for (record_key, subject_key, token) in &cases {
        assert_eq!(raw(&mut conn, record_key), None);
        redis::cmd("SADD")
            .arg(subject_key)
            .arg(token)
            .query::<()>(&mut conn)
            .unwrap();
    }
    store
        .store_issued_grant(
            make_access_token("access"),
            Some(make_refresh_token("refresh")),
            make_bearer_meta("access", Some("refresh")),
        )
        .unwrap();
    for (record_key, subject_key, token) in &cases {
        let before = raw(&mut conn, record_key).unwrap();
        backend(&store).prune_missing_subject_member_for_tests(record_key, subject_key, token);
        assert_eq!(raw(&mut conn, record_key).as_deref(), Some(before.as_str()));
        assert!(member(&mut conn, subject_key, token));
        assert!(store.try_verify_access_token("access").unwrap().is_some());
    }
    // Genuinely absent records still lose their stale membership.
    for (record_key, subject_key, token) in &cases {
        redis::cmd("DEL")
            .arg(record_key)
            .query::<()>(&mut conn)
            .unwrap();
        backend(&store).prune_missing_subject_member_for_tests(record_key, subject_key, token);
        assert!(!member(&mut conn, subject_key, token));
        assert_eq!(raw(&mut conn, record_key), None);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_subject_revocation_prunes_missing_memberships_only() {
    let (store, mut conn) = fixture();
    let keys = backend(&store).keyspace_for_tests();
    let subject_keys = [
        keys.subject_access_key("user"),
        keys.subject_refresh_key("user"),
        keys.subject_bearer_key("user"),
    ];
    for key in &subject_keys {
        redis::cmd("SADD")
            .arg(key)
            .arg("absent")
            .query::<()>(&mut conn)
            .unwrap();
    }
    // Optional cleanup indexes are not authority and need not be erased by
    // a missing subject observation. Retain them for their own cleanup lane.
    let expiry_keys = [
        keys.expiry_access_key(),
        keys.expiry_refresh_key(),
        keys.expiry_bearer_key(),
    ];
    for key in &expiry_keys {
        redis::cmd("ZADD")
            .arg(key)
            .arg(u64::MAX)
            .arg("absent")
            .query::<()>(&mut conn)
            .unwrap();
    }
    assert_eq!(backend(&store).revoke_tokens_by_subject("user").unwrap(), 0);
    for key in &subject_keys {
        assert!(!member(&mut conn, key, "absent"));
    }
    for key in &expiry_keys {
        assert!(redis::cmd("ZSCORE")
            .arg(key)
            .arg("absent")
            .query::<Option<f64>>(&mut conn)
            .unwrap()
            .is_some());
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_subject_revocation_preserves_records_owned_by_another_subject() {
    let (store, mut conn) = fixture();
    store
        .store_issued_grant(
            make_access_token("access"),
            Some(make_refresh_token("refresh")),
            make_bearer_meta("access", Some("refresh")),
        )
        .unwrap();
    let keys = backend(&store).keyspace_for_tests();
    let cases = [
        (
            keys.access_key("access"),
            keys.subject_access_key("wrong-user"),
            keys.subject_access_key("user"),
            "access",
        ),
        (
            keys.refresh_key("refresh"),
            keys.subject_refresh_key("wrong-user"),
            keys.subject_refresh_key("user"),
            "refresh",
        ),
        (
            keys.bearer_key("access"),
            keys.subject_bearer_key("wrong-user"),
            keys.subject_bearer_key("user"),
            "access",
        ),
    ];
    let before: Vec<_> = cases
        .iter()
        .map(|(record, _, _, _)| raw(&mut conn, record).unwrap())
        .collect();
    for (_, wrong_index, _, token) in &cases {
        redis::cmd("SADD")
            .arg(wrong_index)
            .arg(token)
            .query::<()>(&mut conn)
            .unwrap();
    }
    assert_eq!(store.try_revoke_tokens_by_subject("wrong-user").unwrap(), 0);
    for ((record, wrong_index, owner_index, token), expected) in cases.iter().zip(before) {
        assert_eq!(raw(&mut conn, record).as_deref(), Some(expected.as_str()));
        assert!(!member(&mut conn, wrong_index, token));
        assert!(member(&mut conn, owner_index, token));
    }
    assert!(store.try_verify_access_token("access").unwrap().is_some());
    assert!(!store.try_is_refresh_revoked("refresh").unwrap());
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_subject_mismatched_ids_cannot_revoke_unindexed_grant_authority() {
    for kind in ["access", "refresh", "bearer"] {
        let (store, mut conn) = fixture();
        store
            .store_issued_grant(
                make_access_token("target-access"),
                Some(make_refresh_token("target-refresh")),
                make_bearer_meta("target-access", Some("target-refresh")),
            )
            .unwrap();
        let keys = backend(&store).keyspace_for_tests();
        for (index, token) in [
            (keys.subject_access_key("user"), "target-access"),
            (keys.subject_refresh_key("user"), "target-refresh"),
            (keys.subject_bearer_key("user"), "target-access"),
        ] {
            redis::cmd("SREM")
                .arg(index)
                .arg(token)
                .query::<()>(&mut conn)
                .unwrap();
        }
        let (source, alias, index) = match kind {
            "access" => (
                keys.access_key("target-access"),
                keys.access_key("alias"),
                keys.subject_access_key("user"),
            ),
            "refresh" => (
                keys.refresh_key("target-refresh"),
                keys.refresh_key("alias"),
                keys.subject_refresh_key("user"),
            ),
            _ => (
                keys.bearer_key("target-access"),
                keys.bearer_key("alias"),
                keys.subject_bearer_key("user"),
            ),
        };
        let payload = raw(&mut conn, &source).unwrap();
        redis::cmd("SET")
            .arg(&alias)
            .arg(&payload)
            .query::<()>(&mut conn)
            .unwrap();
        redis::cmd("SADD")
            .arg(&index)
            .arg("alias")
            .query::<()>(&mut conn)
            .unwrap();
        assert_eq!(
            store.try_revoke_tokens_by_subject("user").unwrap(),
            0,
            "{kind}"
        );
        assert_eq!(raw(&mut conn, &alias).as_deref(), Some(payload.as_str()));
        assert_eq!(raw(&mut conn, &source).as_deref(), Some(payload.as_str()));
        assert!(!member(&mut conn, &index, "alias"));
        assert!(
            store
                .try_verify_access_token("target-access")
                .unwrap()
                .is_some(),
            "{kind}"
        );
        assert!(
            !store.try_is_refresh_revoked("target-refresh").unwrap(),
            "{kind}"
        );
    }
}
