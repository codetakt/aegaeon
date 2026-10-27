use super::*;

fn clear_redis_upstream_auth_store_for_test(url: &str, key: &str) -> Result<(), String> {
    let client = redis::Client::open(url).map_err(|err| format!("redis test client: {err}"))?;
    let mut conn = client
        .get_connection()
        .map_err(|err| format!("redis test connection: {err}"))?;
    redis::cmd("DEL")
        .arg(key)
        .query::<usize>(&mut conn)
        .map_err(|err| format!("clear redis upstream auth store: {err}"))?;
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_upstream_auth_store_shares_single_use_without_client_secret() -> Result<(), String> {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "upstream-auth-test:v1:{{{}}}:state",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_upstream_auth_store_for_test(url.trim(), &key)?;

    let store_a = UpstreamAuthStore::redis_for_test(url.trim(), &key, 60)?;
    let store_b = UpstreamAuthStore::redis_for_test(url.trim(), &key, 60)?;
    let request = make_upstream_auth_request("state-1", Duration::from_secs(60));

    store_a
        .try_insert(request)
        .map_err(|err| format!("insert request: {err}"))?;
    let consumed = store_b
        .try_consume_bound(
            "state-1",
            &aegaeon_crypto::hash::sha256_hex(b"browser-secret"),
            "https://rp.example/callback",
        )
        .map_err(|err| format!("Redis consume should succeed: {err}"))?
        .ok_or_else(|| "request should be shared through Redis".to_string())?;
    assert_eq!(consumed.state, "state-1");
    assert_eq!(consumed.client_secret, None);
    assert!(
        store_a
            .try_consume_bound(
                "state-1",
                &aegaeon_crypto::hash::sha256_hex(b"browser-secret"),
                "https://rp.example/callback"
            )
            .map_err(|err| format!("Redis consume should succeed: {err}"))?
            .is_none(),
        "upstream auth state must be single-use across nodes"
    );
    Ok(())
}

#[test]
fn upstream_auth_store_reports_backend_unavailable() -> Result<(), String> {
    let store = UpstreamAuthStore::redis_for_test("redis://127.0.0.1:1/", "upstream-down", 60)?;
    let request = make_upstream_auth_request("state-down", Duration::from_secs(60));

    assert!(store.try_insert(request).is_err());
    assert!(store
        .try_consume_bound(
            "state-down",
            &aegaeon_crypto::hash::sha256_hex(b"browser-secret"),
            "https://rp.example/callback"
        )
        .is_err());
    Ok(())
}

#[test]
fn redis_upstream_auth_request_rejects_missing_managed_context() {
    let payload = serde_json::json!({
        "state": "state",
        "nonce": "nonce",
        "code_verifier": null,
        "acr": null,
        "issuer": "https://issuer.example",
        "client_id": "client",
        "client_auth_method": "none",
        "connection_id": uuid::Uuid::new_v4().to_string(),
        "tenant_id": uuid::Uuid::new_v4().to_string(),
        "environment_id": uuid::Uuid::new_v4().to_string(),
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/jwks",
        "redirect_uri": "https://rp.example/callback",
        "return_to": null,
        "max_age": null,
        "require_iss_parameter": true,
        "issuer_policy_version": 1,
        "jit_provisioning_policy": null,
        "attribute_mappings": [],
        "claim_release_policy": null,
        "logout_policy": null,
        "issued_at_epoch_secs": 1,
        "expires_at_epoch_secs": 2
    });

    assert!(serde_json::from_value::<super::RedisUpstreamAuthRequest>(payload).is_err());
}

#[test]
fn upstream_browser_binding_memory_rejections_and_concurrent_single_use() -> Result<(), String> {
    let store = UpstreamAuthStore::new_process_local_for_tests();
    exercise_browser_binding_store(&store)
}

fn exercise_browser_binding_store(store: &UpstreamAuthStore) -> Result<(), String> {
    let request = make_upstream_auth_request("bound-state", Duration::from_secs(60));
    let digest = aegaeon_crypto::hash::sha256_hex(b"browser-secret");
    let uri = request.redirect_uri.clone();
    store.try_insert(request)?;
    assert!(store
        .try_consume_bound("bound-state", &"0".repeat(64), &uri)?
        .is_none());
    for position in [0, 63] {
        let mut wrong = digest.clone().into_bytes();
        wrong[position] = if wrong[position] == b'0' { b'1' } else { b'0' };
        let wrong = String::from_utf8(wrong).map_err(|err| err.to_string())?;
        assert!(store
            .try_consume_bound("bound-state", &wrong, &uri)?
            .is_none());
    }
    assert!(store
        .try_consume_bound("bound-state", &digest, "https://rp.example/wrong")?
        .is_none());
    assert!(store
        .try_consume_bound("bound-state", "invalid", &uri)?
        .is_none());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            let digest = digest.clone();
            let uri = uri.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.try_consume_bound("bound-state", &digest, &uri)
            })
        })
        .collect();
    let mut consumed = 0;
    for thread in threads {
        consumed += usize::from(thread.join().map_err(|_| "thread panicked")??.is_some());
    }
    assert_eq!(consumed, 1);
    for binding in [None, Some(String::new()), Some("invalid".to_string())] {
        let mut request = make_upstream_auth_request("legacy", Duration::from_secs(60));
        request.browser_binding_digest = binding;
        // Use distinct state values so rejected legacy transactions can remain intact.
        request.state = format!("legacy-{:?}", request.browser_binding_digest);
        let state = request.state.clone();
        store.try_insert(request)?;
        assert!(store.try_consume_bound(&state, &digest, &uri)?.is_none());
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn upstream_browser_binding_redis_atomic_consumption_and_legacy_payload() -> Result<(), String> {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    let prefix = format!("upstream-browser-test:{}", uuid::Uuid::new_v4());
    let store = UpstreamAuthStore::redis_for_test(&url, &prefix, 60)?;
    exercise_browser_binding_store(&store)?;
    let request = make_upstream_auth_request("payload", Duration::from_secs(60));
    store.try_insert(request)?;
    let key = format!("{prefix}:{}", aegaeon_crypto::hash::sha256_hex(b"payload"));
    let mut conn = redis::Client::open(url)
        .map_err(|e| e.to_string())?
        .get_connection()
        .map_err(|e| e.to_string())?;
    let payload: String = redis::cmd("GET")
        .arg(&key)
        .query(&mut conn)
        .map_err(|e| e.to_string())?;
    assert!(!payload.contains("browser-secret"));
    assert!(!payload.contains("transient-secret-not-stored"));
    let mut legacy: serde_json::Value =
        serde_json::from_str(&payload).map_err(|e| e.to_string())?;
    legacy
        .as_object_mut()
        .ok_or("object")?
        .remove("browser_binding_digest");
    let decoded: super::RedisUpstreamAuthRequest =
        serde_json::from_value(legacy.clone()).map_err(|e| e.to_string())?;
    assert!(decoded
        .into_request()
        .map_err(|e| e.to_string())?
        .browser_binding_digest
        .is_none());
    redis::cmd("SET")
        .arg(&key)
        .arg(legacy.to_string())
        .arg("PX")
        .arg(5000)
        .query::<()>(&mut conn)
        .map_err(|e| e.to_string())?;
    let digest = aegaeon_crypto::hash::sha256_hex(b"browser-secret");
    assert!(store
        .try_consume_bound("payload", &digest, "https://rp.example/callback")?
        .is_none());
    let still_present: bool = redis::cmd("EXISTS")
        .arg(&key)
        .query(&mut conn)
        .map_err(|e| e.to_string())?;
    assert!(still_present);
    // An otherwise correctly bound stale serialized payload also fails closed.
    legacy["browser_binding_digest"] = serde_json::json!(digest);
    legacy["expires_at_epoch_secs"] = serde_json::json!(1);
    redis::cmd("SET")
        .arg(&key)
        .arg(legacy.to_string())
        .arg("PX")
        .arg(5000)
        .query::<()>(&mut conn)
        .map_err(|e| e.to_string())?;
    assert!(store
        .try_consume_bound("payload", &digest, "https://rp.example/callback")?
        .is_none());
    redis::cmd("DEL")
        .arg(&key)
        .query::<()>(&mut conn)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn redis_upstream_expiry_codec_preserves_nanos_and_legacy_floor(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = make_upstream_auth_request("codec", Duration::from_secs(60));
    request.expires_at = SystemTime::UNIX_EPOCH + Duration::new(42, 987_654_321);
    let dto = super::RedisUpstreamAuthRequest::from_request(&request)?;
    let payload = serde_json::to_string(&dto)?;
    let decoded: super::RedisUpstreamAuthRequest = serde_json::from_str(&payload)?;
    assert_eq!(decoded.into_request()?.expires_at, request.expires_at);
    let mut legacy = serde_json::to_value(&dto)?;
    legacy
        .as_object_mut()
        .unwrap()
        .remove("expires_at_subsec_nanos");
    let decoded: super::RedisUpstreamAuthRequest = serde_json::from_value(legacy)?;
    assert_eq!(
        decoded.into_request()?.expires_at,
        SystemTime::UNIX_EPOCH + Duration::from_secs(42)
    );
    for seconds in [
        0,
        9_007_199_254_740_991,
        9_007_199_254_740_992,
        9_007_199_254_740_993,
        u64::MAX,
    ] {
        let mut value = dto.clone();
        value.expires_at_epoch_secs = seconds;
        let decoded: super::RedisUpstreamAuthRequest =
            serde_json::from_str(&serde_json::to_string(&value)?)?;
        assert_eq!(decoded.expires_at_epoch_secs, seconds);
        assert_eq!(
            decoded.into_request().ok().map(|r| r.expires_at),
            SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, 987_654_321))
        );
    }
    request.expires_at = SystemTime::UNIX_EPOCH - Duration::from_nanos(1);
    assert!(super::RedisUpstreamAuthRequest::from_request(&request).is_err());
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn upstream_browser_binding_redis_live_final_fraction_and_short_expiry(
) -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let prefix = format!("upstream-fraction-test:{}", uuid::Uuid::new_v4());
    let store = UpstreamAuthStore::redis_for_test(&url, &prefix, 60)?;
    let mut conn = redis::Client::open(url)?.get_connection()?;
    // Leave a generous interval inside one second. The old whole-second
    // admission check rejects every request in this final fractional second.
    let seconds = loop {
        let (secs, micros): (u64, u32) = redis::cmd("TIME").query(&mut conn)?;
        if micros < 200_000 {
            break secs;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut request = make_upstream_auth_request("fraction", Duration::from_secs(60));
    request.expires_at = SystemTime::UNIX_EPOCH + Duration::new(seconds, 900_123_456);
    let expiry = request.expires_at;
    let digest = request.browser_binding_digest.clone().unwrap();
    let uri = request.redirect_uri.clone();
    store.try_insert(request)?;
    let consumed = store
        .try_consume_bound("fraction", &digest, &uri)?
        .expect("live final fraction must be admitted");
    assert_eq!(consumed.expires_at, expiry);
    assert!(store
        .try_consume_bound("fraction", &digest, &uri)?
        .is_none());

    let request = make_upstream_auth_request("short", Duration::from_millis(200));
    store.try_insert(request)?;
    let key = format!("{prefix}:{}", aegaeon_crypto::hash::sha256_hex(b"short"));
    let retained: bool = redis::cmd("EXISTS").arg(&key).query(&mut conn)?;
    assert!(retained);
    std::thread::sleep(Duration::from_millis(250));
    assert!(store.try_consume_bound("short", &digest, &uri)?.is_none());
    let retained: bool = redis::cmd("EXISTS").arg(&key).query(&mut conn)?;
    assert!(!retained);
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn upstream_browser_binding_redis_invalid_snapshots_remain_unconsumed(
) -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let prefix = format!("upstream-invalid-test:{}", uuid::Uuid::new_v4());
    let store = UpstreamAuthStore::redis_for_test(&url, &prefix, 60)?;
    let mut conn = redis::Client::open(url)?.get_connection()?;
    let request = make_upstream_auth_request("invalid", Duration::from_secs(60));
    let digest = request.browser_binding_digest.clone().unwrap();
    let uri = request.redirect_uri.clone();
    let dto = super::RedisUpstreamAuthRequest::from_request(&request)?;
    let valid = serde_json::to_value(dto)?;
    let key = format!("{prefix}:{}", aegaeon_crypto::hash::sha256_hex(b"invalid"));
    let mut cases = Vec::new();
    for nanos in [
        json!(-1),
        json!(1.5),
        json!(1_000_000_000u64),
        json!(u64::MAX),
        json!("NaN"),
        json!(null),
    ] {
        let mut payload = valid.clone();
        payload["expires_at_subsec_nanos"] = nanos;
        cases.push((payload.to_string(), true));
    }
    for (field, value, codec_error) in [
        ("state", json!("different-state"), false),
        ("redirect_uri", json!("https://rp.example/wrong"), false),
        ("browser_binding_digest", json!("invalid"), false),
        ("connection_id", json!("invalid"), true),
        ("expires_at_epoch_secs", json!(1), false),
        ("expires_at_epoch_secs", json!(u64::MAX), true),
    ] {
        let mut payload = valid.clone();
        payload[field] = value;
        cases.push((payload.to_string(), codec_error));
    }
    cases.push(("{invalid json".into(), true));
    cases.push((
        valid.to_string().replace(
            "\"expires_at_subsec_nanos\":",
            "\"expires_at_subsec_nanos\":NaN,\"unused\":",
        ),
        true,
    ));
    for (payload, codec_error) in cases {
        redis::cmd("SET")
            .arg(&key)
            .arg(&payload)
            .arg("PX")
            .arg(5000)
            .query::<()>(&mut conn)?;
        let result = store.try_consume_bound("invalid", &digest, &uri);
        if codec_error {
            assert!(result.is_err());
        } else {
            assert!(result?.is_none());
        }
        let remaining: String = redis::cmd("GET").arg(&key).query(&mut conn)?;
        assert_eq!(remaining, payload);
    }
    let mut legacy = valid;
    legacy
        .as_object_mut()
        .unwrap()
        .remove("expires_at_subsec_nanos");
    redis::cmd("SET")
        .arg(&key)
        .arg(legacy.to_string())
        .arg("PX")
        .arg(5000)
        .query::<()>(&mut conn)?;
    let consumed = store
        .try_consume_bound("invalid", &digest, &uri)?
        .expect("legacy valid whole-second deadline remains usable");
    assert_eq!(
        consumed
            .expires_at
            .duration_since(SystemTime::UNIX_EPOCH)?
            .subsec_nanos(),
        0
    );
    Ok(())
}

#[test]
fn upstream_issuer_policy_codec_rejects_legacy_and_unknown_versions(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = make_upstream_auth_request("issuer-policy", Duration::from_secs(60));
    let dto = super::RedisUpstreamAuthRequest::from_request(&request)?;
    let payload = serde_json::to_value(dto)?;
    let mut legacy = payload.clone();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("issuer_policy_version");
    assert!(serde_json::from_value::<super::RedisUpstreamAuthRequest>(legacy).is_err());
    for version in [0, 1, 2, u32::MAX] {
        let mut candidate = payload.clone();
        candidate["issuer_policy_version"] = serde_json::json!(version);
        let decoded: super::RedisUpstreamAuthRequest = serde_json::from_value(candidate)?;
        assert_eq!(decoded.into_request().is_ok(), version == 1);
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn upstream_issuer_policy_redis_rejects_legacy_without_consuming(
) -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let prefix = format!("upstream-issuer-policy:{}", uuid::Uuid::new_v4());
    let store = UpstreamAuthStore::redis_for_test(&url, &prefix, 60)?;
    let mut request = make_upstream_auth_request("issuer-policy", Duration::from_secs(60));
    request.require_iss_parameter = false;
    let digest = request.browser_binding_digest.clone().unwrap();
    let uri = request.redirect_uri.clone();
    store.try_insert(request)?;
    let key = format!(
        "{prefix}:{}",
        aegaeon_crypto::hash::sha256_hex(b"issuer-policy")
    );
    let mut conn = redis::Client::open(url)?.get_connection()?;
    let payload: String = redis::cmd("GET").arg(&key).query(&mut conn)?;
    for version in [None, Some(0), Some(2), Some(u32::MAX)] {
        let mut legacy: serde_json::Value = serde_json::from_str(&payload)?;
        match version {
            None => {
                legacy
                    .as_object_mut()
                    .unwrap()
                    .remove("issuer_policy_version");
            }
            Some(value) => {
                legacy["issuer_policy_version"] = serde_json::json!(value);
            }
        }
        let legacy = legacy.to_string();
        redis::cmd("SET")
            .arg(&key)
            .arg(&legacy)
            .arg("PX")
            .arg(60000)
            .query::<()>(&mut conn)?;
        assert!(store
            .try_consume_bound("issuer-policy", &digest, &uri)
            .is_err());
        let unchanged: String = redis::cmd("GET").arg(&key).query(&mut conn)?;
        assert_eq!(unchanged, legacy);
    }
    redis::cmd("SET")
        .arg(&key)
        .arg(&payload)
        .arg("PX")
        .arg(60000)
        .query::<()>(&mut conn)?;
    assert!(store
        .try_consume_bound("issuer-policy", &digest, &uri)?
        .is_some());
    assert!(store
        .try_consume_bound("issuer-policy", &digest, &uri)?
        .is_none());
    Ok(())
}
