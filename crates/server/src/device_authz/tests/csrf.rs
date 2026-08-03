use super::super::csrf::{CsrfTokenBackend, RedisCsrfTokenStore};
use super::*;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

#[test]
fn csrf_token_generate_and_validate() {
    let store = CsrfTokenStore::new_process_local_for_tests();
    let token = store.generate();
    assert!(!token.is_empty());
    // First validation should succeed (single-use)
    assert!(validate_csrf(&store, &token));
    // Second validation should fail (already consumed)
    assert!(!validate_csrf(&store, &token));
}

#[test]
fn csrf_token_invalid_rejected() {
    let store = CsrfTokenStore::new_process_local_for_tests();
    assert!(!validate_csrf(&store, "nonexistent-token"));
}

#[test]
fn csrf_token_try_validate_reports_backend_unavailable() -> DeviceTestResult {
    let store = CsrfTokenStore {
        backend: CsrfTokenBackend::Redis(must_ok!(
            RedisCsrfTokenStore::new("redis://127.0.0.1:1/", Arc::<str>::from("csrf-down")),
            "redis client construction should not connect",
        )),
        ttl: Duration::from_secs(60),
    };

    assert!(matches!(
        store.try_validate("token"),
        Err(CsrfTokenStoreError::BackendUnavailable(_))
    ));
    Ok(())
}

#[test]
fn csrf_token_unrepresentable_ttl_fails_closed() {
    let store = CsrfTokenStore {
        backend: CsrfTokenBackend::InMemory {
            tokens: RwLock::new(HashMap::new()),
        },
        ttl: Duration::from_secs(u64::MAX),
    };
    assert!(matches!(
        store.try_generate(),
        Err(CsrfTokenStoreError::RetentionOverflow)
    ));
}

#[test]
fn csrf_token_cleanup() {
    let store = CsrfTokenStore {
        backend: CsrfTokenBackend::InMemory {
            tokens: RwLock::new(HashMap::new()),
        },
        ttl: Duration::from_millis(1),
    };
    let token = store.generate();
    thread::sleep(Duration::from_millis(10));
    store.cleanup_expired();
    assert!(!validate_csrf(&store, &token));
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_csrf_token_store_consumes_once_across_instances() -> DeviceTestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let namespace = format!("csrf-test-{}", aegaeon_crypto::rand::random_base64url(8));
    let store_a = CsrfTokenStore {
        backend: CsrfTokenBackend::Redis(must_ok!(
            RedisCsrfTokenStore::new(url.trim(), Arc::<str>::from(namespace.clone())),
            "redis CSRF token store",
        )),
        ttl: Duration::from_secs(60),
    };
    let store_b = CsrfTokenStore {
        backend: CsrfTokenBackend::Redis(must_ok!(
            RedisCsrfTokenStore::new(url.trim(), Arc::<str>::from(namespace)),
            "redis CSRF token store",
        )),
        ttl: Duration::from_secs(60),
    };

    let token = must_ok!(store_a.try_generate(), "generate CSRF token");
    assert!(validate_csrf(&store_b, &token));
    assert!(!validate_csrf(&store_a, &token));
    Ok(())
}
