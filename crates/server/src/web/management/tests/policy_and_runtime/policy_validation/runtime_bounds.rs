
// ---------------------------------------------------------------
// H-4: Policy downgrade guard tests
// ---------------------------------------------------------------

fn base_secure_policy() -> PolicyDocument {
    default_policy_document()
}

#[test]
fn validate_patched_policy_rejects_unrepresentable_seconds() {
    let mut policy = base_secure_policy();
    policy.pkjwt_jti_window_seconds = MAX_SQL_INTEGER_SECONDS + 1;

    assert!(validate_patched_policy(&policy, "req-test").is_err());
}

#[test]
fn validate_patched_policy_rejects_unbounded_replay_windows() -> ManagementTestResult {
    let mut policy = base_secure_policy();
    policy.pkjwt_jti_window_seconds = must_ok!(
        u32::try_from(crate::config::MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS + 1),
        "test replay window bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.jwt_bearer_jti_window_seconds = must_ok!(
        u32::try_from(crate::config::MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS + 1),
        "test bearer replay window bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.request_object_jti_ttl_seconds = must_ok!(
        u32::try_from(crate::config::MAX_REQUEST_OBJECT_JTI_TTL_SECS + 1),
        "test request object JTI TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.jwt_introspection_exp_seconds = must_ok!(
        u32::try_from(crate::config::MAX_JWT_INTROSPECTION_EXP_SECS + 1),
        "test JWT introspection exp bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());
    Ok(())
}

#[test]
fn validate_patched_policy_rejects_invalid_jwks_runtime_policy() {
    let mut policy = base_secure_policy();
    policy.jwks_http_timeout_seconds = 0;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.jwks_http_retries = 11;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.jwks_max_body_bytes = 16 * 1024 * 1024 + 1;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.jwks_local_cache_max_entries = 1_000_001;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.jwks_http_retries = 0;
    policy.jwks_refresh_skew_seconds = 0;
    assert!(validate_patched_policy(&policy, "req-test").is_ok());
}

#[test]
fn validate_patched_policy_accepts_promoted_ps256_client_jwt_algorithm() {
    let mut policy = base_secure_policy();
    policy.client_jwt_allowed_algs = vec!["RS256".to_string(), "PS256".to_string()];

    assert!(validate_patched_policy(&policy, "req-test").is_ok());
}

#[test]
fn validate_patched_policy_rejects_unpromoted_ps384_client_jwt_algorithm() {
    let mut policy = base_secure_policy();
    policy.client_jwt_allowed_algs = vec!["PS384".to_string()];

    assert!(validate_patched_policy(&policy, "req-test").is_err());
}

#[test]
fn validate_patched_policy_rejects_unbounded_token_ttl_and_leeway() -> ManagementTestResult {
    let mut policy = base_secure_policy();
    policy.access_token_time_to_live_seconds = must_ok!(
        u32::try_from(crate::config::MAX_ACCESS_TOKEN_TTL_SECS + 1),
        "test access token TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.jwt_leeway_seconds = must_ok!(
        u32::try_from(crate::config::MAX_JWT_LEEWAY_SECS + 1),
        "test JWT leeway bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.ssa_leeway_seconds = must_ok!(
        u32::try_from(crate::config::MAX_SSA_LEEWAY_SECS + 1),
        "test SSA leeway bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.jose_header_max_len = must_ok!(
        u32::try_from(crate::config::MAX_JOSE_HEADER_LEN + 1),
        "test JOSE header length bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.auth_session_ttl_seconds = must_ok!(
        u32::try_from(crate::config::MAX_AUTH_SESSION_TTL_SECS + 1),
        "test auth session TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.auth_max_sessions = must_ok!(
        u32::try_from(crate::config::MAX_AUTH_MAX_SESSIONS + 1),
        "test auth max sessions bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.oidc_logout_session_ttl_seconds = must_ok!(
        u32::try_from(crate::oidc::session::MAX_LOGOUT_SESSION_TTL_SECS + 1),
        "test OIDC logout session TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.oidc_backchannel_logout_timeout_seconds = must_ok!(
        u32::try_from(crate::oidc::config::MAX_BACKCHANNEL_LOGOUT_TIMEOUT_SECS + 1),
        "test OIDC back-channel logout timeout bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.stepup_challenge_ttl_seconds = must_ok!(
        u32::try_from(crate::config::MAX_STEPUP_CHALLENGE_TTL_SECS + 1),
        "test step-up challenge TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.upstream_auth_ttl_seconds = must_ok!(
        u32::try_from(crate::config::MAX_UPSTREAM_AUTH_TTL_SECS + 1),
        "test upstream auth TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.upstream_logout_relay_ttl_seconds = must_ok!(
        u32::try_from(crate::config::MAX_UPSTREAM_LOGOUT_RELAY_TTL_SECS + 1),
        "test upstream logout relay TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.upstream_discovery_cache_ttl_seconds = must_ok!(
        u32::try_from(crate::upstream::MAX_UPSTREAM_METADATA_CACHE_TTL_SECS + 1),
        "test upstream discovery cache TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.upstream_discovery_cache_max_entries =
        crate::upstream::MAX_UPSTREAM_METADATA_CACHE_MAX_ENTRIES + 1;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.upstream_jwks_cache_ttl_seconds = 0;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.upstream_jwks_cache_max_entries = 0;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.cleanup_interval_seconds = must_ok!(
        u32::try_from(crate::config::MAX_CLEANUP_INTERVAL_SECS + 1),
        "test cleanup interval bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.runtime_config_monitor_interval_seconds = 0;
    assert!(validate_patched_policy(&policy, "req-test").is_err());
    Ok(())
}

#[test]
fn validate_patched_policy_rejects_unbounded_dpop_iat_window() -> ManagementTestResult {
    let mut policy = base_secure_policy();
    policy.dpop_iat_window_seconds = must_ok!(
        u32::try_from(crate::config::MAX_DPOP_IAT_WINDOW_SECS + 1),
        "test DPoP iat window bound fits u32"
    );

    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.dpop_nonce_ttl_seconds = must_ok!(
        u32::try_from(crate::config::MAX_DPOP_NONCE_TTL_SECS + 1),
        "test DPoP nonce TTL bound fits u32"
    );

    assert!(validate_patched_policy(&policy, "req-test").is_err());
    Ok(())
}

#[test]
fn validate_patched_policy_rejects_unsafe_mtls_base_url() {
    let mut policy = base_secure_policy();
    policy.mtls_base_url = Some("http://mtls.auth.example.com".to_string());

    assert!(validate_patched_policy(&policy, "req-test").is_err());
}

#[test]
fn validate_patched_policy_rejects_unimplemented_dcr_sender_method() {
    let mut policy = base_secure_policy();
    policy.dcr_allowed_sender_methods = vec!["mtls".to_string()];

    assert!(validate_patched_policy(&policy, "req-test").is_err());
}

#[test]
fn validate_patched_policy_rejects_invalid_ssa_public_key_pem() {
    let mut policy = base_secure_policy();
    policy.ssa_jwt_pem = Some("not a PEM public key".to_string());

    assert!(validate_patched_policy(&policy, "req-test").is_err());
}

#[test]
fn validate_patched_policy_accepts_valid_ssa_public_key_pem() {
    let mut policy = base_secure_policy();
    policy.ssa_jwt_pem = Some(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa2048-public.pem"
        ))
        .to_string(),
    );

    assert!(validate_patched_policy(&policy, "req-test").is_ok());
}

#[test]
fn validate_patched_policy_rejects_unsupported_grant_type() {
    let mut policy = base_secure_policy();
    policy.allowed_grant_types = vec!["authorization_code".to_string(), "urn:custom".to_string()];

    assert!(validate_patched_policy(&policy, "req-test").is_err());
}

#[test]
fn validate_patched_policy_rejects_invalid_federation_cache_policy() -> ManagementTestResult {
    let mut policy = base_secure_policy();
    policy.federation_entity_cache_ttl_seconds = 0;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.federation_trust_chain_cache_ttl_seconds = must_ok!(
        u32::try_from(crate::federation::MAX_FEDERATION_CACHE_TTL_SECS + 1),
        "test federation cache TTL bound fits u32"
    );
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.federation_cache_max_entries = 0;
    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.federation_cache_max_entries = crate::federation::MAX_FEDERATION_CACHE_MAX_ENTRIES + 1;
    assert!(validate_patched_policy(&policy, "req-test").is_err());
    Ok(())
}

#[test]
fn upstream_metadata_cache_uses_management_policy_snapshot() -> ManagementTestResult {
    let mut policy = base_secure_policy();
    policy.upstream_discovery_cache_ttl_seconds = 600;
    policy.upstream_discovery_cache_max_entries = 111;
    policy.upstream_jwks_cache_ttl_seconds = 900;
    policy.upstream_jwks_cache_max_entries = 222;

    let discovery_cache = must_ok!(
        crate::upstream::NonAuthoritativeMetadataCache::<String>::try_new_non_authoritative_with_ttl_secs_and_max_entries(
            "upstream_discovery_cache_ttl_seconds",
            u64::from(policy.upstream_discovery_cache_ttl_seconds),
            "upstream_discovery_cache_max_entries",
            policy.upstream_discovery_cache_max_entries,
        ),
        "valid upstream discovery cache policy"
    );
    let jwks_cache = crate::upstream::NonAuthoritativeMetadataCache::<String>::try_new_non_authoritative_with_ttl_secs_and_max_entries(
        "upstream_jwks_cache_ttl_seconds",
        u64::from(policy.upstream_jwks_cache_ttl_seconds),
        "upstream_jwks_cache_max_entries",
        policy.upstream_jwks_cache_max_entries,
    )
    .map_err(|err| std::io::Error::other(format!("valid upstream jwks cache policy: {err:?}")))?;

    assert_eq!(discovery_cache.ttl(), std::time::Duration::from_secs(600));
    assert_eq!(discovery_cache.max_entries(), 111);
    assert_eq!(jwks_cache.ttl(), std::time::Duration::from_secs(900));
    assert_eq!(jwks_cache.max_entries(), 222);
    Ok(())
}

#[test]
fn federation_cache_config_uses_management_policy_snapshot() -> ManagementTestResult {
    let mut policy = base_secure_policy();
    policy.federation_entity_cache_ttl_seconds = 900;
    policy.federation_trust_chain_cache_ttl_seconds = 1800;
    policy.federation_cache_max_entries = 250;
    policy.federation_outbound_allowed_domains = vec![
        " Example.COM. ".to_string(),
        "example.com".to_string(),
    ];

    let config = must_ok!(
        crate::federation::FederationCacheConfig::try_from_management_policy(&policy),
        "valid federation cache policy"
    );

    assert_eq!(config.entity_cache_ttl, std::time::Duration::from_secs(900));
    assert_eq!(
        config.trust_chain_cache_ttl,
        std::time::Duration::from_secs(1800)
    );
    assert_eq!(config.cache_max_entries, 250);
    assert_eq!(config.outbound_allowed_domains, vec!["example.com"]);
    Ok(())
}

#[test]
fn validate_federation_policy_rejects_invalid_outbound_domain_allowlist() {
    let mut policy = base_secure_policy();
    policy.federation_outbound_allowed_domains = vec!["https://example.com".to_string()];

    assert!(validate_patched_policy(&policy, "req-test").is_err());
    assert!(validate_federation_policy_for_environment(
        &policy,
        "https://auth.example.com",
        "req-test"
    )
    .is_err());
    assert!(crate::federation::FederationCacheConfig::try_from_management_policy(&policy).is_err());
}

#[test]
fn validate_policy_rejects_invalid_upstream_outbound_domain_allowlist() {
    let mut policy = base_secure_policy();
    policy.upstream_outbound_allowed_domains = vec!["https://example.com".to_string()];

    assert!(validate_patched_policy(&policy, "req-test").is_err());
    assert!(validate_federation_policy_for_environment(
        &policy,
        "https://auth.example.com",
        "req-test"
    )
    .is_err());
    assert!(crate::config::ServerConfig::default()
        .with_management_policy(&policy)
        .is_err());
}

#[test]
fn federation_policy_allows_non_entity_issuer_when_federation_is_disabled() {
    let policy = base_secure_policy();
    assert!(validate_federation_policy_for_environment(
        &policy,
        "http://localhost:8080",
        "req-test"
    )
    .is_ok());
}

#[test]
fn validate_patched_policy_rejects_unadvertised_acr_values() {
    let mut policy = base_secure_policy();
    policy.acr_values_supported = vec!["urn:pwd".to_string()];
    policy.default_acr = Some("urn:mfa".to_string());

    assert!(validate_patched_policy(&policy, "req-test").is_err());

    let mut policy = base_secure_policy();
    policy.acr_values_supported = vec!["urn:pwd".to_string()];
    policy.local_password_acr = Some("urn:mfa".to_string());

    assert!(validate_patched_policy(&policy, "req-test").is_err());
}
