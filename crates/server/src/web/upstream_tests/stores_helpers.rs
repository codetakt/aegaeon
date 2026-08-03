
// -----------------------------------------------------------------------
// UpstreamAuthStore round-trip tests
// -----------------------------------------------------------------------

fn make_auth_request(
    state: &str,
    ttl: std::time::Duration,
) -> crate::upstream::UpstreamAuthRequest {
    let now = std::time::SystemTime::now();
    crate::upstream::UpstreamAuthRequest {
        state: state.to_string(),
        nonce: "nonce".to_string(),
        code_verifier: None,
        acr: None,
        issuer: "https://issuer.example".to_string(),
        client_id: "client".to_string(),
        client_secret: None,
        client_auth_method: "none".to_string(),
        context: crate::upstream::UpstreamConnectionContext::new(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        ),
        token_endpoint: "https://issuer.example/token".to_string(),
        jwks_uri: "https://issuer.example/jwks".to_string(),
        redirect_uri: "https://rp.example/callback".to_string(),
        return_to: None,
        max_age: None,
        require_iss_parameter: true,
        jit_provisioning_policy: None,
        attribute_mappings: Vec::new(),
        claim_release_policy: None,
        logout_policy: None,
        issued_at: now,
        expires_at: now + ttl,
    }
}

#[test]
fn upstream_auth_store_insert_and_consume() -> TestResult {
    let store = crate::upstream::UpstreamAuthStore::new_process_local_for_tests();
    let req = make_auth_request("s1", std::time::Duration::from_secs(60));
    store.try_insert(req)?;
    let consumed = require_some(store.try_consume("s1")?, "expected state s1 to be consumed")?;
    assert_eq!(consumed.state, "s1");
    Ok(())
}

#[test]
fn upstream_auth_store_insert_rejects_fresh_state_collision() -> TestResult {
    let store = crate::upstream::UpstreamAuthStore::new_process_local_for_tests();
    store.try_insert(make_auth_request("s-collision", std::time::Duration::from_secs(60)))?;
    let err = require_err(
        store.try_insert(make_auth_request(
            "s-collision",
            std::time::Duration::from_secs(60),
        )),
        "fresh state collision must fail",
    )?;
    assert_eq!(err, "upstream auth state already exists");
    Ok(())
}

#[test]
fn upstream_auth_store_consume_is_single_use() -> TestResult {
    let store = crate::upstream::UpstreamAuthStore::new_process_local_for_tests();
    let req = make_auth_request("s2", std::time::Duration::from_secs(60));
    store.try_insert(req)?;
    assert!(store.try_consume("s2")?.is_some());
    assert!(
        store.try_consume("s2")?.is_none(),
        "second consume must return None"
    );
    Ok(())
}

#[test]
fn select_upstream_jit_reuse_candidate_rejects_email_collision_for_reject_policy() -> TestResult {
    let policy = UpstreamJitProvisioningPolicy {
        enabled: true,
        require_verified_email: true,
        domain_allowlist: Vec::new(),
        collision_policy: UpstreamJitProvisioningCollisionPolicy::RejectExistingEmail,
        initial_status: UpstreamJitProvisioningInitialStatus::Active,
    };
    let matches = vec![UpstreamResolvedUser {
        end_user_id: uuid::Uuid::new_v4(),
        subject: "existing-subject".to_string(),
        status: "ACTIVE".to_string(),
        account_link_connection_id: None,
    }];
    let err = require_err(
        select_upstream_jit_reuse_candidate(&policy, "new-subject", &matches),
        "expected reject-existing-email collision",
    )?;
    assert_eq!(
        err,
        "upstream email is already associated with a different local user"
    );
    Ok(())
}

#[test]
fn select_upstream_jit_reuse_candidate_reuses_single_matching_user() -> TestResult {
    let policy = UpstreamJitProvisioningPolicy {
        enabled: true,
        require_verified_email: true,
        domain_allowlist: Vec::new(),
        collision_policy: UpstreamJitProvisioningCollisionPolicy::ReuseExistingEmail,
        initial_status: UpstreamJitProvisioningInitialStatus::Active,
    };
    let existing_id = uuid::Uuid::new_v4();
    let matches = vec![UpstreamResolvedUser {
        end_user_id: existing_id,
        subject: "existing-subject".to_string(),
        status: "ACTIVE".to_string(),
        account_link_connection_id: None,
    }];
    let candidate = select_upstream_jit_reuse_candidate(&policy, "new-subject", &matches)
        .map_err(ToString::to_string)?;
    let candidate = require_some(candidate, "expected reuse candidate")?;
    assert_eq!(candidate.end_user_id, existing_id);
    Ok(())
}

#[test]
fn select_upstream_jit_reuse_candidate_rejects_multiple_reuse_matches() -> TestResult {
    let policy = UpstreamJitProvisioningPolicy {
        enabled: true,
        require_verified_email: true,
        domain_allowlist: Vec::new(),
        collision_policy: UpstreamJitProvisioningCollisionPolicy::ReuseExistingEmail,
        initial_status: UpstreamJitProvisioningInitialStatus::Active,
    };
    let matches = vec![
        UpstreamResolvedUser {
            end_user_id: uuid::Uuid::new_v4(),
            subject: "first".to_string(),
            status: "ACTIVE".to_string(),
            account_link_connection_id: None,
        },
        UpstreamResolvedUser {
            end_user_id: uuid::Uuid::new_v4(),
            subject: "second".to_string(),
            status: "ACTIVE".to_string(),
            account_link_connection_id: None,
        },
    ];
    let err = require_err(
        select_upstream_jit_reuse_candidate(&policy, "new-subject", &matches),
        "expected multiple reuse matches to be rejected",
    )?;
    assert_eq!(err, "upstream email resolves to multiple local users");
    Ok(())
}

#[test]
fn upstream_account_link_upsert_sql_is_identity_preserving() {
    let normalized_sql = UPSTREAM_ACCOUNT_LINK_UPSERT_SQL
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert!(normalized_sql.contains(
        "ON CONFLICT (environment_id, upstream_issuer, upstream_sub_hash) DO UPDATE"
    ));
    assert!(normalized_sql.contains(
        "WHERE aegaeon.account_links.end_user_id = EXCLUDED.end_user_id"
    ));
    assert!(normalized_sql.contains(
        "AND aegaeon.account_links.connection_id = EXCLUDED.connection_id"
    ));
}

#[test]
fn upstream_auth_store_consume_rejects_expired() -> TestResult {
    let store = crate::upstream::UpstreamAuthStore::new_process_local_for_tests();
    // TTL of zero means already expired at insert time.
    let req = make_auth_request("s3", std::time::Duration::from_secs(0));
    store.try_insert(req)?;
    // SystemTime::now() >= expires_at -> expired.
    assert!(store.try_consume("s3")?.is_none());
    Ok(())
}

#[test]
fn upstream_auth_store_consume_rejects_unknown_state() -> TestResult {
    let store = crate::upstream::UpstreamAuthStore::new_process_local_for_tests();
    assert!(store.try_consume("nonexistent")?.is_none());
    Ok(())
}

fn clear_redis_upstream_logout_relay_store_for_test(url: &str, key: &str) -> TestResult {
    let client = redis::Client::open(url).map_err(|err| format!("redis test client: {err}"))?;
    let mut conn = client
        .get_connection()
        .map_err(|err| format!("redis test connection: {err}"))?;
    redis::cmd("DEL")
        .arg(key)
        .query::<usize>(&mut conn)
        .map_err(|err| format!("clear redis upstream logout relay store: {err}"))?;
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_upstream_logout_relay_store_shares_single_use() -> TestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "upstream-logout-relay-test:v1:{{{}}}:state",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_upstream_logout_relay_store_for_test(url.trim(), &key)?;

    let store_a = UpstreamLogoutRelayStore::redis_for_test(
        url.trim(),
        &key,
        std::time::Duration::from_secs(60),
    )?;
    let store_b = UpstreamLogoutRelayStore::redis_for_test(
        url.trim(),
        &key,
        std::time::Duration::from_secs(60),
    )?;
    let relay = UpstreamLogoutRelayState {
        incident_id: Some(uuid::Uuid::new_v4()),
        downstream_redirect_uri: "https://rp.example/logout-complete".to_string(),
        downstream_state: Some("client-state".to_string()),
    };

    store_a
        .try_insert("relay-token", relay.clone())
        .map_err(|err| format!("relay insert should succeed: {err}"))?;
    assert_eq!(
        store_b
            .try_take("relay-token")
            .map_err(|err| format!("relay take should succeed: {err}"))?,
        Some(relay)
    );
    assert!(
        store_a
            .try_take("relay-token")
            .map_err(|err| format!("relay take should succeed: {err}"))?
            .is_none(),
        "logout relay state must be single-use across nodes"
    );
    Ok(())
}

#[test]
fn upstream_logout_relay_store_reports_backend_unavailable() -> TestResult {
    let store = UpstreamLogoutRelayStore::redis_for_test(
        "redis://127.0.0.1:1/",
        "logout-relay-down",
        std::time::Duration::from_secs(60),
    )?;
    let relay = UpstreamLogoutRelayState {
        incident_id: Some(uuid::Uuid::new_v4()),
        downstream_redirect_uri: "https://rp.example/logout-complete".to_string(),
        downstream_state: Some("client-state".to_string()),
    };

    assert!(store.try_insert("relay-token", relay).is_err());
    assert!(store.try_take("relay-token").is_err());
    Ok(())
}

// -----------------------------------------------------------------------
// NonAuthoritativeMetadataCache tests
// -----------------------------------------------------------------------

#[test]
fn metadata_cache_insert_and_get() -> TestResult {
    let cache = crate::upstream::NonAuthoritativeMetadataCache::<String>::with_ttl_secs(60);
    cache.try_insert("k", "v".to_string())?;
    assert_eq!(cache.try_get("k")?, Some("v".to_string()));
    Ok(())
}

#[test]
fn metadata_cache_get_returns_none_when_empty() -> TestResult {
    let cache = crate::upstream::NonAuthoritativeMetadataCache::<String>::with_ttl_secs(60);
    assert_eq!(cache.try_get("missing")?, None);
    Ok(())
}

#[test]
fn metadata_cache_expired_entry_returns_none() -> TestResult {
    let cache = crate::upstream::NonAuthoritativeMetadataCache::<String>::with_ttl_secs(0);
    cache.try_insert("k", "v".to_string())?;
    // TTL 0 → expires immediately.
    assert_eq!(cache.try_get("k")?, None);
    Ok(())
}

#[test]
fn metadata_cache_invalidate() -> TestResult {
    let cache = crate::upstream::NonAuthoritativeMetadataCache::<String>::with_ttl_secs(60);
    cache.try_insert("k", "v".to_string())?;
    cache.try_invalidate("k")?;
    assert_eq!(cache.try_get("k")?, None);
    Ok(())
}

#[test]
fn metadata_cache_cleanup_removes_expired() -> TestResult {
    let cache = crate::upstream::NonAuthoritativeMetadataCache::<String>::with_ttl_secs(0);
    cache.try_insert("a", "1".to_string())?;
    cache.try_insert("b", "2".to_string())?;
    cache.try_cleanup_expired()?;
    assert_eq!(cache.len()?, 0);
    Ok(())
}

// -----------------------------------------------------------------------
// Helper function tests
// -----------------------------------------------------------------------

#[test]
fn build_upstream_redirect_uri_formats_correctly() {
    assert_eq!(
        build_upstream_redirect_uri("https://as.example", "conn-1"),
        "https://as.example/oauth/upstream/conn-1/callback"
    );
    // Trailing slash should be stripped.
    assert_eq!(
        build_upstream_redirect_uri("https://as.example/", "conn-2"),
        "https://as.example/oauth/upstream/conn-2/callback"
    );
}

#[test]
fn validate_https_endpoint_accepts_valid() {
    assert!(validate_https_endpoint("https://example.com/path", "test").is_ok());
}

#[test]
fn validate_https_endpoint_rejects_http() {
    let result = validate_https_endpoint("http://example.com", "test");
    assert!(result.is_err(), "http should be rejected");
    let Err(err) = result else {
        return;
    };
    assert!(err.contains("https"));
}

#[test]
fn validate_https_endpoint_rejects_credentials() {
    let result = validate_https_endpoint("https://user:pass@example.com", "test");
    assert!(result.is_err(), "credentials should be rejected");
    let Err(err) = result else {
        return;
    };
    assert!(err.contains("credentials"));
}

#[test]
fn validate_https_endpoint_rejects_query_or_fragment() {
    for endpoint in [
        "https://example.com/path?state=bad",
        "https://example.com/path#fragment",
    ] {
        let result = validate_https_endpoint(endpoint, "test");
        assert!(result.is_err(), "{endpoint} should be rejected");
        let Err(err) = result else {
            return;
        };
        assert!(err.contains("query or fragment"));
    }
}

#[test]
fn pkce_challenge_is_s256() {
    // PKCE S256: BASE64URL(SHA256(verifier))
    let verifier = "test_verifier_value";
    let challenge = crate::upstream::pkce_challenge(verifier);
    // Verify it's deterministic and non-empty.
    assert!(!challenge.is_empty());
    assert_eq!(challenge, crate::upstream::pkce_challenge(verifier));
    // Verify it changes with different input.
    assert_ne!(challenge, crate::upstream::pkce_challenge("other"));
}

#[test]
fn local_login_rate_limit_keys_cover_ip_principal_and_pair_buckets() -> TestResult {
    let remote: SocketAddr = "198.51.100.7:443"
        .parse()
        .map_err(|err| format!("parse socket address: {err}"))?;
    let keys = login_rate_limit_keys("local-login", remote, " User@Example.COM ");
    let normalized_keys = login_rate_limit_keys("local-login", remote, "user@example.com");

    assert_eq!(keys, normalized_keys);
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0], "local-login:ip:198.51.100.7");
    assert!(keys[1].starts_with("local-login:principal:"));
    assert!(keys[2].starts_with("local-login:pair:198.51.100.7:"));
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[1], keys[2]);
    Ok(())
}

#[test]
fn local_login_rate_limit_allows_rejects_after_any_bucket_exhausts() -> TestResult {
    let limiter = VerificationRateLimiter::new_process_local_for_tests();
    let remote: SocketAddr = "198.51.100.7:443"
        .parse()
        .map_err(|err| format!("parse socket address: {err}"))?;
    let keys = login_rate_limit_keys("local-login", remote, "user@example.com");

    for _ in 0..10 {
        assert!(login_rate_limit_allows(&limiter, &keys)?);
    }
    assert!(!login_rate_limit_allows(&limiter, &keys)?);
    Ok(())
}

#[test]
fn local_login_rate_limit_allows_does_not_partially_consume_buckets() -> TestResult {
    let limiter = VerificationRateLimiter::new_process_local_for_tests();
    let remote: SocketAddr = "198.51.100.7:443"
        .parse()
        .map_err(|err| format!("parse socket address: {err}"))?;
    let keys = login_rate_limit_keys("local-login", remote, "user@example.com");

    for _ in 0..10 {
        assert!(limiter
            .try_check(&keys[1])
            .map_err(|err| format!("rate limiter: {err}"))?);
    }
    assert!(!login_rate_limit_allows(&limiter, &keys)?);

    for _ in 0..10 {
        assert!(
            limiter
                .try_check(&keys[0])
                .map_err(|err| format!("rate limiter: {err}"))?,
            "failed composite admission must not consume the IP bucket"
        );
    }
    assert!(!limiter
        .try_check(&keys[0])
        .map_err(|err| format!("rate limiter: {err}"))?);
    Ok(())
}

#[test]
fn validate_return_to_accepts_relative_path() {
    let result = validate_return_to(Some("/dashboard".to_string()));
    assert!(result.is_ok(), "relative return_to should be accepted");
    let Ok(validated) = result else {
        return;
    };
    assert_eq!(validated, Some("/dashboard".to_string()));
}

#[test]
fn validate_return_to_accepts_none() {
    let result = validate_return_to(None);
    assert!(result.is_ok(), "missing return_to should be accepted");
    let Ok(validated) = result else {
        return;
    };
    assert_eq!(validated, None);
}

#[test]
fn no_cache_redirect_response_sets_location_and_no_store() -> TestResult {
    let response = no_cache_redirect_response("/continue");
    assert_eq!(response.status(), StatusCode::FOUND);
    let headers = response.headers();
    assert_eq!(
        headers.get(header::LOCATION).and_then(|value| value.to_str().ok()),
        Some("/continue")
    );
    assert!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("no-store")),
        "redirect responses in auth flows must not be cached"
    );
    Ok(())
}
