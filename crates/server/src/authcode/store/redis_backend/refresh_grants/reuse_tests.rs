//! Exact-CAS controls for the production denial script, without physical cleanup.
use super::*;
use std::time::Duration;

struct Fixture {
    backend: RedisTokenStoreBackend,
    conn: redis::Connection,
    previous_key: String,
    record: RefreshGrantRecord,
}

impl Fixture {
    fn new() -> Self {
        let url = std::env::var("AEGAEON_TEST_REDIS_URL").unwrap();
        let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
            "reuse-denial-{}",
            uuid::Uuid::new_v4()
        ));
        let backend = RedisTokenStoreBackend::new(&url, &namespace).unwrap();
        let mut conn = backend.connection().unwrap();
        let record = RefreshGrantRecord {
            version: 1,
            reference: RefreshGrantRef::new(),
            client_id: "client".into(),
            user_id: "user".into(),
            revoked: false,
            // A cjson round-trip would lose this exact integer or fractional part.
            retain_until: UNIX_EPOCH + Duration::new(9_007_199_254_740_995, 123_456_789),
        };
        let previous_key = backend.keyspace.refresh_key("previous");
        redis::cmd("SET")
            .arg(&previous_key)
            .arg("rotated-observation")
            .query::<()>(&mut conn)
            .unwrap();
        redis::cmd("SET")
            .arg(backend.keyspace.refresh_grant_key(&record.reference.id))
            .arg(encode_redis_json(&record).unwrap())
            .query::<()>(&mut conn)
            .unwrap();
        Self {
            backend,
            conn,
            previous_key,
            record,
        }
    }

    fn plan(&mut self) -> GrantCommit {
        self.backend
            .descendant_grant_commit(
                &mut self.conn,
                Some(&self.record.reference),
                "client",
                "user",
                self.record.retain_until + Duration::from_secs(100),
            )
            .unwrap()
            .unwrap()
    }

    fn stored(&mut self) -> RefreshGrantRecord {
        let raw: String = redis::cmd("GET")
            .arg(
                self.backend
                    .keyspace
                    .refresh_grant_key(&self.record.reference.id),
            )
            .query(&mut self.conn)
            .unwrap();
        serde_json::from_str(&raw).unwrap()
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_reuse_denial_survives_no_cleanup_and_preserves_exact_retention() {
    let mut f = Fixture::new();
    let plan = f.plan();
    let lock = f.backend.keyspace.lock_key();
    redis::cmd("SET")
        .arg(&lock)
        .arg("unavailable-cleanup-lock")
        .query::<()>(&mut f.conn)
        .unwrap();
    assert_eq!(
        plan.deny_reuse(&mut f.conn, &f.previous_key, "rotated-observation")
            .unwrap(),
        "reused"
    );
    // Discard the caller's connection and perform no family cleanup.
    f.conn = f.backend.connection().unwrap();
    let mut expected = f.record.clone();
    expected.revoked = true;
    assert_eq!(f.stored(), expected);
    assert_eq!(
        redis::cmd("GET")
            .arg(&lock)
            .query::<String>(&mut f.conn)
            .unwrap(),
        "unavailable-cleanup-lock"
    );
    assert_eq!(
        redis::cmd("GET")
            .arg(&f.previous_key)
            .query::<String>(&mut f.conn)
            .unwrap(),
        "rotated-observation"
    );
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
fn redis_reuse_denial_rejects_stale_refresh_and_grant_observations() {
    for change_grant in [false, true] {
        let mut f = Fixture::new();
        let plan = f.plan();
        let mut expected = f.record.clone();
        let key = if change_grant {
            expected.retain_until += Duration::from_secs(20);
            f.backend.keyspace.refresh_grant_key(&expected.reference.id)
        } else {
            f.previous_key.clone()
        };
        let value = if change_grant {
            encode_redis_json(&expected).unwrap()
        } else {
            "newer-refresh".into()
        };
        redis::cmd("SET")
            .arg(&key)
            .arg(&value)
            .query::<()>(&mut f.conn)
            .unwrap();
        assert_eq!(
            plan.deny_reuse(&mut f.conn, &f.previous_key, "rotated-observation")
                .unwrap(),
            "stale"
        );
        assert_eq!(f.stored(), expected);
        assert_eq!(
            redis::cmd("GET")
                .arg(key)
                .query::<String>(&mut f.conn)
                .unwrap(),
            value
        );
        assert!(!redis::cmd("EXISTS")
            .arg(f.backend.keyspace.version_key())
            .query::<bool>(&mut f.conn)
            .unwrap());
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_reuse_denial_does_not_report_success_after_version_failure() {
    for version in ["bad", "9223372036854775807"] {
        let mut f = Fixture::new();
        let plan = f.plan();
        redis::cmd("SET")
            .arg(f.backend.keyspace.version_key())
            .arg(version)
            .query::<()>(&mut f.conn)
            .unwrap();
        assert!(plan
            .deny_reuse(&mut f.conn, &f.previous_key, "rotated-observation")
            .is_err());
        assert_eq!(f.stored(), f.record);
    }
}
