use super::*;

struct Fixture {
    backend: RedisTokenStoreBackend,
    conn: redis::Connection,
    observer: redis::Connection,
    token: AccessToken,
    raw: String,
}

impl Fixture {
    fn new() -> Self {
        let url = std::env::var("AEGAEON_TEST_REDIS_URL").unwrap();
        let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
            "cleanup-cas-{}",
            uuid::Uuid::new_v4()
        ));
        let backend = RedisTokenStoreBackend::new(&url, &namespace).unwrap();
        let mut conn = backend.connection().unwrap();
        let observer = backend.connection().unwrap();
        let token = AccessToken::new("client".into(), "user".into(), None, 600);
        let raw = encode_redis_json(&token).unwrap();
        redis::cmd("SET")
            .arg(backend.keyspace.access_key(&token.token))
            .arg(&raw)
            .query::<()>(&mut conn)
            .unwrap();
        redis::cmd("SADD")
            .arg(backend.keyspace.subject_access_key("user"))
            .arg(&token.token)
            .query::<()>(&mut conn)
            .unwrap();
        Self {
            backend,
            conn,
            observer,
            token,
            raw,
        }
    }

    fn mutation(&self) -> RedisTokenMutation {
        let mut mutation = RedisTokenMutation::default();
        mutation
            .observe_record(
                self.backend.keyspace.access_key(&self.token.token),
                Some(self.raw.clone()),
            )
            .unwrap();
        mutation.delete_access_token(self.token.token.clone());
        mutation
    }

    fn stored(&mut self) -> Option<String> {
        redis::cmd("GET")
            .arg(self.backend.keyspace.access_key(&self.token.token))
            .query(&mut self.conn)
            .unwrap()
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_cleanup_rejects_replacement_since_record_observation() {
    let mut f = Fixture::new();
    let mutation = f.mutation();
    let mut replacement = f.token.clone();
    replacement.user_id = "new-owner".into();
    let raw = encode_redis_json(&replacement).unwrap();
    redis::cmd("SET")
        .arg(f.backend.keyspace.access_key(&f.token.token))
        .arg(&raw)
        .query::<()>(&mut f.observer)
        .unwrap();
    redis::cmd("SADD")
        .arg(f.backend.keyspace.subject_access_key("new-owner"))
        .arg(&f.token.token)
        .query::<()>(&mut f.observer)
        .unwrap();
    assert!(f
        .backend
        .apply_token_mutation(&mut f.conn, mutation, true)
        .is_err());
    assert_eq!(f.stored().as_deref(), Some(raw.as_str()));
    assert!(redis::cmd("SISMEMBER")
        .arg(f.backend.keyspace.subject_access_key("new-owner"))
        .arg(&f.token.token)
        .query::<bool>(&mut f.conn)
        .unwrap());
    assert!(!redis::cmd("EXISTS")
        .arg(f.backend.keyspace.version_key())
        .query::<bool>(&mut f.conn)
        .unwrap());
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_cleanup_aborted_exec_is_not_success_and_unwatches() {
    let mut f = Fixture::new();
    let key = f.backend.keyspace.access_key(&f.token.token);
    // Invalidate this connection's WATCH deterministically, without changing
    // the observed bytes. Adding the same WATCH does not clear invalidation.
    redis::cmd("WATCH")
        .arg(&key)
        .query::<()>(&mut f.conn)
        .unwrap();
    redis::cmd("SET")
        .arg(&key)
        .arg(&f.raw)
        .query::<()>(&mut f.observer)
        .unwrap();
    let mutation = f.mutation();
    assert!(f
        .backend
        .apply_token_mutation(&mut f.conn, mutation, true)
        .is_err());
    assert_eq!(f.stored().as_deref(), Some(f.raw.as_str()));
    assert!(!redis::cmd("EXISTS")
        .arg(f.backend.keyspace.version_key())
        .query::<bool>(&mut f.conn)
        .unwrap());
    // The failed attempt leaves no active WATCH; a fresh unchanged plan commits.
    let mutation = f.mutation();
    f.backend
        .apply_token_mutation(&mut f.conn, mutation, true)
        .unwrap();
    assert_eq!(f.stored(), None);
    assert!(!redis::cmd("SISMEMBER")
        .arg(f.backend.keyspace.subject_access_key("user"))
        .arg(&f.token.token)
        .query::<bool>(&mut f.conn)
        .unwrap());
    assert_eq!(
        redis::cmd("GET")
            .arg(f.backend.keyspace.version_key())
            .query::<u64>(&mut f.conn)
            .unwrap(),
        1
    );
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_cleanup_repeated_read_cannot_replace_original_observation() {
    let mut f = Fixture::new();
    let mut mutation = f.mutation();
    let key = f.backend.keyspace.access_key(&f.token.token);
    redis::cmd("SET")
        .arg(&key)
        .arg("replacement")
        .query::<()>(&mut f.observer)
        .unwrap();
    assert!(RedisTokenStoreBackend::get_observed_json::<AccessToken>(
        &mut f.conn,
        key.clone(),
        &mut mutation
    )
    .is_err());
    assert_eq!(
        mutation.observed_records.get(&key),
        Some(&Some(f.raw.clone()))
    );
    assert_eq!(f.stored().as_deref(), Some("replacement"));
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_cleanup_requires_observations_for_all_deletions_and_supports() {
    let mut f = Fixture::new();
    let token = &f.token.token;
    let mut plans = Vec::new();
    let mut access = RedisTokenMutation::default();
    access.delete_access_token(token.clone());
    plans.push(access);
    let mut refresh = RedisTokenMutation::default();
    refresh.delete_refresh_token(token.clone());
    plans.push(refresh);
    let mut refresh = RedisTokenMutation::default();
    refresh.delete_refresh_token(token.clone());
    refresh
        .observe_record(f.backend.keyspace.refresh_key(token), None)
        .unwrap();
    plans.push(refresh); // Missing implicit child-index observation.
    let mut bearer = RedisTokenMutation::default();
    bearer.delete_bearer_token(token.clone());
    plans.push(bearer);
    let mut bearer = RedisTokenMutation::default();
    bearer.delete_bearer_token(token.clone());
    bearer
        .observe_record(f.backend.keyspace.bearer_key(token), None)
        .unwrap();
    plans.push(bearer); // Missing access-absence authorization for SREM.
    let mut revoked = RedisTokenMutation::default();
    revoked.delete_revoked_token(token.clone());
    plans.push(revoked);
    let mut link = RedisTokenMutation::default();
    link.delete_key(f.backend.keyspace.refresh_successor_key(token));
    plans.push(link);
    for plan in plans {
        assert!(f
            .backend
            .apply_token_mutation(&mut f.conn, plan, true)
            .is_err());
        assert_eq!(f.stored().as_deref(), Some(f.raw.as_str()));
        assert!(!redis::cmd("EXISTS")
            .arg(f.backend.keyspace.version_key())
            .query::<bool>(&mut f.conn)
            .unwrap());
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_expiry_planning_preserves_replacements_and_new_records() {
    use std::time::{Duration, SystemTime};
    for missing in [false, true] {
        let mut f = Fixture::new();
        let now = SystemTime::now();
        let mut expired = f.token.clone();
        expired.created_at = now - Duration::from_secs(1000);
        let key = f.backend.keyspace.access_key(&expired.token);
        if missing {
            redis::cmd("DEL")
                .arg(&key)
                .query::<()>(&mut f.conn)
                .unwrap();
        } else {
            redis::cmd("SET")
                .arg(&key)
                .arg(encode_redis_json(&expired).unwrap())
                .query::<()>(&mut f.conn)
                .unwrap();
        }
        redis::cmd("ZADD")
            .arg(f.backend.keyspace.expiry_access_key())
            .arg(0)
            .arg(&expired.token)
            .query::<()>(&mut f.conn)
            .unwrap();
        let mut mutation = RedisTokenMutation::default();
        f.backend
            .collect_expired_tokens(&mut f.conn, now, &mut mutation)
            .unwrap();
        assert!(mutation.delete_access_tokens.contains(&expired.token));
        redis::cmd("SET")
            .arg(&key)
            .arg(&f.raw)
            .query::<()>(&mut f.observer)
            .unwrap();
        assert!(f
            .backend
            .apply_token_mutation(&mut f.conn, mutation, true)
            .is_err());
        assert_eq!(f.stored().as_deref(), Some(f.raw.as_str()));
        // A new plan sees the live record and leaves it alone.
        let mut mutation = RedisTokenMutation::default();
        f.backend
            .collect_expired_tokens(&mut f.conn, now, &mut mutation)
            .unwrap();
        assert!(!mutation.delete_access_tokens.contains(&expired.token));
        f.backend
            .apply_token_mutation(&mut f.conn, mutation, false)
            .unwrap();
        assert_eq!(f.stored().as_deref(), Some(f.raw.as_str()));
    }
}
