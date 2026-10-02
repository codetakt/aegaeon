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
