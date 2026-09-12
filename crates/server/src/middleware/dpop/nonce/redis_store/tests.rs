use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<RedisDpopNonceStore, Box<dyn std::error::Error>> {
    Ok(RedisDpopNonceStore::new(
        &std::env::var("AEGAEON_TEST_REDIS_URL")?,
        format!("bounded-nonce-test-{}", uuid::Uuid::new_v4()).into(),
    )?)
}

fn issued(store: &RedisDpopNonceStore, role: DpopEndpointRole) -> Result<String, String> {
    store
        .issue_nonce(role, Duration::from_secs(60))
        .map_err(|e| format!("{e:?}"))
}

fn accepted(
    store: &RedisDpopNonceStore,
    role: DpopEndpointRole,
    value: &str,
) -> Result<bool, String> {
    store
        .validate_nonce(role, value)
        .map_err(|e| format!("{e:?}"))
}

fn record(
    conn: &mut redis::Connection,
    key: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let raw: String = redis::cmd("GET").arg(key).query(conn)?;
    Ok(serde_json::from_str(&raw)?)
}

fn deadlines(conn: &mut redis::Connection, key: &str, fields: &[&str]) -> TestResult {
    let mut value = record(conn, key)?;
    for field in fields {
        value[*field] = serde_json::json!(0);
    }
    redis::cmd("SET")
        .arg(key)
        .arg(serde_json::to_string(&value)?)
        .arg("KEEPTTL")
        .query::<()>(conn)?;
    Ok(())
}

#[test]
#[ignore = "requires private Redis"]
fn redis_nonce_challenge_volume_keeps_two_role_records_and_fixed_deadlines() -> TestResult {
    let store = fixture()?;
    let mut conn = store.client.get_connection()?;
    for role in [
        DpopEndpointRole::AuthorizationServer,
        DpopEndpointRole::ResourceServer,
    ] {
        let first = issued(&store, role)?;
        let key = store.nonce_key(role);
        let before = record(&mut conn, &key)?;
        for _ in 0..128 {
            assert_eq!(issued(&store, role)?, first);
            assert!(accepted(&store, role, &first)?);
            assert!(!accepted(&store, role, "unknown")?);
        }
        let after = record(&mut conn, &key)?;
        assert_eq!(before, after, "traffic must not extend either deadline");
        let ttl: i64 = redis::cmd("PTTL").arg(&key).query(&mut conn)?;
        assert!((1..=120_000).contains(&ttl));
        assert_eq!(after.as_object().ok_or("record object")?.len(), 3);
    }
    let pattern = store
        .nonce_key(DpopEndpointRole::AuthorizationServer)
        .trim_end_matches(":as")
        .to_owned()
        + ":*";
    let keys: Vec<String> = redis::cmd("KEYS").arg(pattern).query(&mut conn)?;
    assert_eq!(
        keys.len(),
        2,
        "one record per role regardless of request volume"
    );
    Ok(())
}

#[test]
#[ignore = "requires private Redis"]
fn redis_nonce_rotation_grace_expiry_and_idle_do_not_resurrect_values() -> TestResult {
    let store = fixture()?;
    let role = DpopEndpointRole::AuthorizationServer;
    let key = store.nonce_key(role);
    let mut conn = store.client.get_connection()?;
    let first = issued(&store, role)?;
    // Only manipulate retained deadlines in this private fixture. Production
    // uses Redis TIME; this exercises the actual scripts without wall sleeps.
    deadlines(&mut conn, &key, &["rotate_at"])?;
    let second = issued(&store, role)?;
    assert_ne!(first, second);
    assert!(accepted(&store, role, &first)?);
    assert!(accepted(&store, role, &second)?);
    deadlines(&mut conn, &key, &["previous_until"])?;
    assert!(!accepted(&store, role, &first)?);
    assert!(accepted(&store, role, &second)?);
    deadlines(&mut conn, &key, &["rotate_at", "valid_until"])?;
    assert!(!accepted(&store, role, &second)?);
    let third = issued(&store, role)?;
    assert_ne!(second, third);
    assert!(
        !accepted(&store, role, &second)?,
        "idle-expired value must not gain new grace"
    );
    assert!(accepted(&store, role, &third)?);
    redis::cmd("PEXPIREAT")
        .arg(&key)
        .arg(1)
        .query::<()>(&mut conn)?;
    assert!(!accepted(&store, role, &third)?);
    assert_ne!(issued(&store, role)?, third);
    Ok(())
}

#[test]
#[ignore = "requires private Redis"]
fn redis_nonce_backend_errors_are_not_invalid_credentials_or_issued_challenges() -> TestResult {
    let store = fixture()?;
    let role = DpopEndpointRole::ResourceServer;
    let nonce = issued(&store, role)?;
    let key = store.nonce_key(role);
    let mut conn = store.client.get_connection()?;
    redis::cmd("SET")
        .arg(&key)
        .arg("wrong-type")
        .arg("PX")
        .arg(60_000)
        .query::<()>(&mut conn)?;
    assert!(matches!(
        store.issue_nonce(role, Duration::from_secs(60)),
        Err(DpopError::BackendUnavailable(_))
    ));
    assert!(matches!(
        store.validate_nonce(role, &nonce),
        Err(DpopError::BackendUnavailable(_))
    ));
    Ok(())
}

#[test]
#[ignore = "requires private Redis"]
fn redis_nonce_retention_failures_do_not_publish_or_reuse_partial_records() -> TestResult {
    let store = fixture()?;
    let role = DpopEndpointRole::ResourceServer;
    let key = store.nonce_key(role);
    let mut conn = store.client.get_connection()?;
    let username = format!("nonce-{}", uuid::Uuid::new_v4());
    let password = uuid::Uuid::new_v4().to_string();
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&username)
        .arg("on")
        .arg(format!(">{password}"))
        .arg(format!("~{key}"))
        .arg("+eval")
        .arg("+evalsha")
        .arg("+script|load")
        .arg("+get")
        .arg("+pttl")
        .arg("+time")
        .query::<()>(&mut conn)?;
    let mut url = url::Url::parse(&std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    url.set_username(&username).map_err(|()| "username")?;
    url.set_password(Some(&password)).map_err(|()| "password")?;
    let restricted = RedisDpopNonceStore::new(url.as_str(), Arc::clone(&store.namespace))?;
    assert!(matches!(
        restricted.issue_nonce(role, Duration::from_secs(60)),
        Err(DpopError::BackendUnavailable(_))
    ));
    assert_eq!(redis::cmd("EXISTS").arg(&key).query::<i64>(&mut conn)?, 0);
    let first = issued(&store, role)?;
    deadlines(&mut conn, &key, &["rotate_at"])?;
    let before = record(&mut conn, &key)?;
    assert!(matches!(
        restricted.issue_nonce(role, Duration::from_secs(60)),
        Err(DpopError::BackendUnavailable(_))
    ));
    assert_eq!(record(&mut conn, &key)?, before);
    assert!(accepted(&store, role, &first)?);
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&username)
        .arg("+set")
        .query::<()>(&mut conn)?;
    let second = issued(&restricted, role)?;
    assert!(accepted(&restricted, role, &second)?);
    assert_ne!(first, second);
    redis::cmd("PERSIST").arg(&key).query::<()>(&mut conn)?;
    assert!(matches!(
        store.issue_nonce(role, Duration::from_secs(60)),
        Err(DpopError::BackendUnavailable(_))
    ));
    assert!(matches!(
        store.validate_nonce(role, &second),
        Err(DpopError::BackendUnavailable(_))
    ));
    redis::cmd("DEL").arg(&key).query::<()>(&mut conn)?;
    redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&username)
        .query::<()>(&mut conn)?;
    Ok(())
}

#[test]
#[ignore = "requires private Redis"]
fn redis_nonce_unrepresentable_expiry_fails_before_any_write() -> TestResult {
    let store = fixture()?;
    let role = DpopEndpointRole::AuthorizationServer;
    let key = store.nonce_key(role);
    for milliseconds in [i64::MAX.unsigned_abs() / 2, 4_000_000_000_000_000] {
        let ttl = Duration::from_millis(milliseconds);
        assert!(matches!(
            store.issue_nonce(role, ttl),
            Err(DpopError::BackendUnavailable(_))
        ));
        assert_eq!(
            redis::cmd("EXISTS")
                .arg(&key)
                .query::<i64>(&mut store.client.get_connection()?)?,
            0
        );
    }
    assert!(accepted(&store, role, &issued(&store, role)?)?);
    Ok(())
}
