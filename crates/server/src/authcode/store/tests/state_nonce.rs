#[test]
fn state_rejected_within_ttl() {
    let store = AuthCodeStore::new_process_local_with_ttl_for_tests(Duration::from_secs(10));
    let code1 = make_test_code(Some("state-1"), None);
    assert!(store.store_code(code1).is_ok());

    // Same state should be rejected
    let code2 = make_test_code(Some("state-1"), None);
    let err = store.store_code(code2);
    assert!(err.is_err());
    assert!(matches!(err.as_ref(), Err(message) if message == "State already used"));
}

#[test]
fn state_allowed_after_ttl_expires() {
    let store = AuthCodeStore::new_process_local_with_ttl_for_tests(Duration::from_millis(20));
    let code1 = make_test_code(Some("state-ttl-test"), None);
    assert!(store.store_code(code1).is_ok());

    // Wait for TTL to expire
    thread::sleep(Duration::from_millis(30));

    // Same state should now be allowed
    let code2 = make_test_code(Some("state-ttl-test"), None);
    assert!(store.store_code(code2).is_ok());
}

#[test]
fn nonce_rejected_within_ttl() {
    let store = AuthCodeStore::new_process_local_with_ttl_for_tests(Duration::from_secs(10));
    let code1 = make_test_code(None, Some("nonce-1"));
    assert!(store.store_code(code1).is_ok());

    // Same nonce should be rejected
    let code2 = make_test_code(None, Some("nonce-1"));
    let err = store.store_code(code2);
    assert!(err.is_err());
    assert!(matches!(err.as_ref(), Err(message) if message == "Nonce already used"));
}

#[test]
fn nonce_allowed_after_ttl_expires() {
    let store = AuthCodeStore::new_process_local_with_ttl_for_tests(Duration::from_millis(20));
    let code1 = make_test_code(None, Some("nonce-ttl-test"));
    assert!(store.store_code(code1).is_ok());

    // Wait for TTL to expire
    thread::sleep(Duration::from_millis(30));

    // Same nonce should now be allowed
    let code2 = make_test_code(None, Some("nonce-ttl-test"));
    assert!(store.store_code(code2).is_ok());
}

#[test]
fn cleanup_removes_expired_states_and_nonces() {
    let store = AuthCodeStore::new_process_local_with_ttl_for_tests(Duration::from_millis(20));

    // Store multiple states and nonces
    let code1 = make_test_code(Some("cleanup-state-1"), Some("cleanup-nonce-1"));
    let code2 = make_test_code(Some("cleanup-state-2"), Some("cleanup-nonce-2"));
    assert!(store.store_code(code1).is_ok());
    assert!(store.store_code(code2).is_ok());

    assert_eq!(store.state_count(), 2);
    assert_eq!(store.nonce_count(), 2);

    // Wait for TTL to expire
    thread::sleep(Duration::from_millis(30));

    // Run cleanup
    store.cleanup_expired();

    // States and nonces should be removed
    assert_eq!(store.state_count(), 0);
    assert_eq!(store.nonce_count(), 0);
}

#[test]
fn different_states_and_nonces_allowed() {
    let store = AuthCodeStore::new_process_local_with_ttl_for_tests(Duration::from_secs(10));

    let code1 = make_test_code(Some("state-a"), Some("nonce-a"));
    let code2 = make_test_code(Some("state-b"), Some("nonce-b"));

    assert!(store.store_code(code1).is_ok());
    assert!(store.store_code(code2).is_ok());

    assert_eq!(store.state_count(), 2);
    assert_eq!(store.nonce_count(), 2);
}

#[test]
fn snapshot_returns_state_and_nonce_keys() {
    let store = AuthCodeStore::new_process_local_with_ttl_for_tests(Duration::from_secs(10));

    let code = make_test_code(Some("snap-state"), Some("snap-nonce"));
    assert!(store.store_code(code).is_ok());

    let snapshot = store.snapshot();
    assert!(snapshot.used_states.contains("snap-state"));
    assert!(snapshot.used_nonces.contains("snap-nonce"));
}
