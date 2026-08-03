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
        .try_consume("state-1")
        .map_err(|err| format!("Redis consume should succeed: {err}"))?
        .ok_or_else(|| "request should be shared through Redis".to_string())?;
    assert_eq!(consumed.state, "state-1");
    assert_eq!(consumed.client_secret, None);
    assert!(
        store_a
            .try_consume("state-1")
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
    assert!(store.try_consume("state-down").is_err());
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
