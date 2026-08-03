use super::*;
use std::sync::Arc;
use std::time::Duration;

fn redis_device_code_store_for_test(
    url: &str,
    key: &str,
    interval_secs: u64,
) -> Result<DeviceCodeStore, String> {
    Ok(DeviceCodeStore {
        backend: DeviceCodeStoreBackend::Redis(must_ok!(
            RedisDeviceCodeStoreBackend::new_with_prefix(url, Arc::<str>::from(key.to_string())),
            "redis device code store",
        )),
        ttl: Duration::from_secs(60),
        default_interval_secs: interval_secs,
    })
}

fn clear_redis_device_code_store_for_test(url: &str, key: &str) -> DeviceTestResult {
    let client = must_ok!(redis::Client::open(url), "redis test client");
    let mut conn = must_ok!(client.get_connection(), "redis test connection");
    let keyspace = RedisDeviceCodeKeyspace::from_test_prefix(Arc::<str>::from(key.to_string()));
    let keys = must_ok!(
        redis::cmd("KEYS")
            .arg(format!("{}:*", keyspace.prefix))
            .query::<Vec<String>>(&mut conn),
        "scan redis device code store",
    );
    if !keys.is_empty() {
        must_ok!(
            redis::cmd("DEL").arg(keys).query::<usize>(&mut conn),
            "clear redis device code v2 store",
        );
    }
    Ok(())
}

#[test]
fn redis_device_code_try_poll_reports_backend_unavailable() -> DeviceTestResult {
    let store = redis_device_code_store_for_test(
        "redis://127.0.0.1:1/",
        "device-code-test:v2:{unavailable}",
        0,
    )?;

    let err = must_err!(
        store.try_poll("device-code", "client1", None, None),
        "unavailable Redis device code store must be reported",
    );

    assert!(err.contains("device code store backend unavailable"));

    let count_err = must_err!(
        store.try_active_count(),
        "unavailable Redis device count must be reported",
    );

    assert!(count_err.contains("device code store backend unavailable"));
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_device_code_store_shares_poll_backoff_and_single_use() -> DeviceTestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "device-code-test:v2:{{{}}}",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_device_code_store_for_test(url.trim(), &key)?;

    let store_a = redis_device_code_store_for_test(url.trim(), &key, 0)?;
    let store_b = redis_device_code_store_for_test(url.trim(), &key, 0)?;
    let resp = store_a.create(
        "client1",
        Some("openid"),
        None,
        "https://example.com/device",
    );

    assert!(must_ok!(
        store_b.try_lookup_by_user_code(&resp.user_code),
        "redis user-code lookup should be confirmed",
    )
    .is_some());
    assert!(must_ok!(
        store_b.try_approve(&resp.user_code, "user123"),
        "redis approval should be confirmed",
    ));
    assert!(matches!(
        poll_device_code(&store_a, &resp.device_code, "client1", None, None),
        DevicePollResult::Approved { .. }
    ));
    assert!(matches!(
        poll_device_code(&store_b, &resp.device_code, "client1", None, None),
        DevicePollResult::ExpiredToken
    ));
    assert_eq!(store_a.active_count(), 0);

    let throttled_a = redis_device_code_store_for_test(url.trim(), &key, 5)?;
    let throttled_b = redis_device_code_store_for_test(url.trim(), &key, 5)?;
    let throttled = throttled_a.create("client2", None, None, "https://example.com/device");
    assert!(matches!(
        poll_device_code(&throttled_a, &throttled.device_code, "client2", None, None),
        DevicePollResult::AuthorizationPending
    ));
    assert!(matches!(
        poll_device_code(&throttled_b, &throttled.device_code, "client2", None, None),
        DevicePollResult::SlowDown
    ));
    Ok(())
}
