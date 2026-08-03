use super::*;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

type TestResult = Result<(), String>;

#[test]
fn device_code_stored_as_sha256_hash() -> TestResult {
    let store = DeviceCodeStore::new_process_local_for_tests();
    let resp = store.create(
        "client1",
        Some("openid"),
        None,
        "https://example.com/device",
    );

    // The raw device code should not appear in the store keys
    let by_hash = read_lock(store.in_memory_by_hash()?, "test_device_code_hash")
        .map_err(|err| format!("device store read lock: {err}"))?;
    assert!(!by_hash.contains_key(&resp.device_code));

    // But the hash should be present
    let hash = hash_device_code(&resp.device_code);
    assert!(by_hash.contains_key(&hash));
    Ok(())
}

#[test]
fn basic_device_flow() {
    // Use 0s interval to avoid slow_down in unit tests
    let store = DeviceCodeStore::new_process_local_with_ttl_and_interval_for_tests(60, 0);
    let resp = store.create(
        "client1",
        Some("openid"),
        None,
        "https://example.com/device",
    );

    // Poll before approval → authorization_pending
    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(result, DevicePollResult::AuthorizationPending));

    // Approve via user code
    let raw_code = normalize_user_code(&resp.user_code);
    assert!(approve(&store, &raw_code, "user123"));

    // Poll after approval → Approved (single-use)
    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(
        &result,
        DevicePollResult::Approved {
            user_id,
            scope,
            resource,
            client_id,
        } if user_id == "user123"
            && scope.as_deref() == Some("openid")
            && resource.is_none()
            && client_id == "client1"
    ));

    // DA-5: second poll after consumption → ExpiredToken
    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(result, DevicePollResult::ExpiredToken));
}

#[test]
fn user_denial() {
    let store = DeviceCodeStore::new_process_local_with_ttl_and_interval_for_tests(60, 0);
    let resp = store.create("client1", None, None, "https://example.com/device");

    let raw_code = normalize_user_code(&resp.user_code);
    assert!(deny(&store, &raw_code));

    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(result, DevicePollResult::AccessDenied));
}

#[test]
fn expired_device_code() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(0); // immediate expiry
    let resp = store.create("client1", None, None, "https://example.com/device");

    // Small delay to ensure expiry
    thread::sleep(Duration::from_millis(10));

    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(result, DevicePollResult::ExpiredToken));
}

#[test]
fn device_code_unrepresentable_ttl_fails_closed() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(u64::MAX);
    assert!(store
        .try_create("client1", None, None, "https://example.com/device")
        .is_none());
}

#[test]
fn rate_limiting_slow_down() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(60);
    let resp = store.create("client1", None, None, "https://example.com/device");

    // First poll → ok (authorization_pending)
    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(result, DevicePollResult::AuthorizationPending));

    // Immediate second poll → slow_down (within default 5s interval)
    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(result, DevicePollResult::SlowDown));
}

#[test]
fn environment_scoping() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(60);
    let resp = store.create(
        "client1",
        None,
        Some("env-abc"),
        "https://example.com/device",
    );

    // Poll with wrong environment → ExpiredToken
    let result = poll_device_code(&store, &resp.device_code, "client1", Some("env-xyz"), None);
    assert!(matches!(result, DevicePollResult::ExpiredToken));

    // Poll with correct environment → AuthorizationPending
    let result = poll_device_code(&store, &resp.device_code, "client1", Some("env-abc"), None);
    assert!(matches!(result, DevicePollResult::AuthorizationPending));
}

#[test]
fn client_binding() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(60);
    let resp = store.create("client1", None, None, "https://example.com/device");

    // Poll with wrong client → ExpiredToken
    let result = poll_device_code(&store, &resp.device_code, "client2", None, None);
    assert!(matches!(result, DevicePollResult::ExpiredToken));
}

#[test]
fn approval_preserves_requested_scope() {
    let store = DeviceCodeStore::new_process_local_with_ttl_and_interval_for_tests(60, 0);
    let resp = store.create(
        "client1",
        Some("read write"),
        None,
        "https://example.com/device",
    );

    let raw_code = normalize_user_code(&resp.user_code);
    assert!(approve(&store, &raw_code, "user123"));

    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(
        result,
        DevicePollResult::Approved {
            scope,
            ..
        } if scope.as_deref() == Some("read write")
    ));
}

#[test]
fn bound_resource_must_match_poll_request() -> TestResult {
    let store = DeviceCodeStore::new_process_local_with_ttl_and_interval_for_tests(60, 0);
    let resp = store
        .try_create_with_resource(
            "client1",
            Some("read"),
            Some("https://api.example.com"),
            None,
            "https://example.com/device",
        )
        .ok_or_else(|| "device grant should be created".to_string())?;

    let raw_code = normalize_user_code(&resp.user_code);
    assert!(approve(&store, &raw_code, "user123"));

    let result = poll_device_code(
        &store,
        &resp.device_code,
        "client1",
        None,
        Some("https://other.example.com"),
    );
    assert!(matches!(result, DevicePollResult::InvalidTarget));

    let result = poll_device_code(
        &store,
        &resp.device_code,
        "client1",
        None,
        Some("https://api.example.com"),
    );
    assert!(matches!(
        result,
        DevicePollResult::Approved {
            resource,
            ..
        } if resource.as_deref() == Some("https://api.example.com")
    ));
    Ok(())
}

#[test]
fn unbound_resource_rejects_poll_resource_escalation() {
    let store = DeviceCodeStore::new_process_local_with_ttl_and_interval_for_tests(60, 0);
    let resp = store.create("client1", None, None, "https://example.com/device");

    let raw_code = normalize_user_code(&resp.user_code);
    assert!(approve(&store, &raw_code, "user123"));

    let result = poll_device_code(
        &store,
        &resp.device_code,
        "client1",
        None,
        Some("https://api.example.com"),
    );
    assert!(matches!(result, DevicePollResult::InvalidTarget));

    let result = poll_device_code(&store, &resp.device_code, "client1", None, None);
    assert!(matches!(result, DevicePollResult::Approved { .. }));
}

#[test]
fn slow_down_poll_interval_saturates() -> TestResult {
    let store = DeviceCodeStore::new_process_local_with_ttl_and_interval_for_tests(60, 0);
    let device_code = "slow-down-device-code";
    let hash = hash_device_code(device_code);
    let entry = DeviceCodeEntry {
        user_code: "ACDEFGHJ".to_string(),
        client_id: "client1".to_string(),
        scope: None,
        resource: None,
        environment_id: None,
        status: DeviceAuthzStatus::Pending,
        expires_at: SystemTime::now() + Duration::from_secs(60),
        last_poll_at: Some(Instant::now()),
        poll_interval_secs: u64::MAX,
        consumed: false,
    };
    write_lock(
        store.in_memory_by_hash()?,
        "test_slow_down_poll_interval_saturates",
    )
    .map_err(|err| format!("device store write lock: {err}"))?
    .insert(hash.clone(), entry);

    let result = poll_device_code(&store, device_code, "client1", None, None);

    assert!(matches!(result, DevicePollResult::SlowDown));
    let map = read_lock(
        store.in_memory_by_hash()?,
        "test_slow_down_poll_interval_saturates",
    )
    .map_err(|err| format!("device store read lock: {err}"))?;
    assert_eq!(
        map.get(&hash).map(|entry| entry.poll_interval_secs),
        Some(u64::MAX)
    );
    Ok(())
}

#[test]
fn user_code_collision_does_not_overwrite_existing_mapping() -> TestResult {
    let store = DeviceCodeStore::new_process_local_with_ttl_and_interval_for_tests(60, 0);
    let verification_uri = "https://example.com/device";
    let user_code = "ACDEFGHJ".to_string();
    let first_device_code = "first-device-code".to_string();
    let first_hash = hash_device_code(&first_device_code);
    let first_entry = DeviceCodeEntry {
        user_code: user_code.clone(),
        client_id: "client1".to_string(),
        scope: Some("read".to_string()),
        resource: None,
        environment_id: None,
        status: DeviceAuthzStatus::Pending,
        expires_at: SystemTime::now() + Duration::from_secs(60),
        last_poll_at: None,
        poll_interval_secs: 0,
        consumed: false,
    };

    let first_response = match store.try_insert_entry(
        first_device_code,
        &first_hash,
        &user_code,
        first_entry,
        verification_uri,
    ) {
        DeviceCodeCreateResult::Created(response) => response,
        _ => return Err("first entry should insert".to_string()),
    };

    let second_device_code = "second-device-code".to_string();
    let second_hash = hash_device_code(&second_device_code);
    let second_entry = DeviceCodeEntry {
        user_code,
        client_id: "client2".to_string(),
        scope: None,
        resource: None,
        environment_id: None,
        status: DeviceAuthzStatus::Pending,
        expires_at: SystemTime::now() + Duration::from_secs(60),
        last_poll_at: None,
        poll_interval_secs: 0,
        consumed: false,
    };

    assert!(matches!(
        store.try_insert_entry(
            second_device_code,
            &second_hash,
            "ACDEFGHJ",
            second_entry,
            verification_uri,
        ),
        DeviceCodeCreateResult::Collision
    ));
    assert_eq!(store.active_count(), 1);
    assert_eq!(
        lookup_by_user_code(&store, &first_response.user_code),
        Some(DeviceUserCodeLookup {
            client_id: "client1".to_string(),
            scope: Some("read".to_string()),
            resource: None,
        })
    );
    Ok(())
}

#[test]
fn cleanup_removes_expired_entries() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(0);
    let _ = store.create("client1", None, None, "https://example.com/device");
    let _ = store.create("client2", None, None, "https://example.com/device");

    assert_eq!(store.active_count(), 2);

    thread::sleep(Duration::from_millis(10));
    store.cleanup_expired();

    assert_eq!(store.active_count(), 0);
}

#[test]
fn lookup_by_user_code_returns_pending_entry() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(60);
    let resp = store.create("client1", Some("read"), None, "https://example.com/device");

    let result = lookup_by_user_code(&store, &resp.user_code);
    assert_eq!(
        result.as_ref().map(|lookup| lookup.client_id.as_str()),
        Some("client1")
    );
    assert_eq!(
        result.as_ref().and_then(|lookup| lookup.scope.as_deref()),
        Some("read")
    );
    assert_eq!(
        result
            .as_ref()
            .and_then(|lookup| lookup.resource.as_deref()),
        None
    );
}

#[test]
fn try_lookup_by_user_code_reports_missing_without_backend_error() -> TestResult {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(60);

    let result = store
        .try_lookup_by_user_code("missing")
        .map_err(|err| format!("in-memory user-code lookup should be confirmed: {err}"))?;

    assert!(result.is_none());
    Ok(())
}

#[test]
fn lookup_by_user_code_returns_none_after_approval() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(60);
    let resp = store.create("client1", None, None, "https://example.com/device");

    let raw = normalize_user_code(&resp.user_code);
    let _ = approve(&store, &raw, "user1");

    assert!(lookup_by_user_code(&store, &resp.user_code).is_none());
}

#[test]
fn double_approval_rejected() {
    let store = DeviceCodeStore::new_process_local_with_ttl_for_tests(60);
    let resp = store.create("client1", None, None, "https://example.com/device");

    let raw = normalize_user_code(&resp.user_code);
    assert!(approve(&store, &raw, "user1"));
    // Second approval should fail (status is no longer Pending)
    assert!(!approve(&store, &raw, "user2"));
}

#[test]
fn verification_uri_complete_contains_user_code() {
    let store = DeviceCodeStore::new_process_local_for_tests();
    let resp = store.create("client1", None, None, "https://example.com/device");
    assert!(resp
        .verification_uri_complete
        .as_deref()
        .is_some_and(|complete| complete.starts_with("https://example.com/device?user_code=")));
    assert!(resp
        .verification_uri_complete
        .as_deref()
        .is_some_and(|complete| complete.contains(&resp.user_code)));
}
