
#[test]
fn apply_policy_patch_normalizes_lists_and_clears_optional_strings() {
    let policy = default_policy_document();
    let patch = PolicyPatchRequest {
        base_configuration_version_id: "00000000-0000-0000-0000-000000000000".to_string(),
        pkce_required: None,
        dcr_enabled: None,
        dcr_everparse_runtime_enabled: None,
        require_state_parameter: None,
        strict_authorize_redirect: None,
        require_client_auth_token: None,
        require_client_auth_par: None,
        require_client_auth_introspection: None,
        require_client_auth_revocation: None,
        sender_constraint: None,
        require_scope_subset: None,
        require_audience_match: None,
        retain_refresh_chain: None,
        enforce_refresh_sender_binding: None,
        dpop_strict: None,
        dpop_iat_window_seconds: None,
        dpop_require_nonce: None,
        dpop_nonce_ttl_seconds: None,
        require_pushed_authorization_requests: None,
        par_expires_in_seconds: None,
        device_code_ttl_seconds: None,
        device_code_poll_interval_seconds: None,
        activation_token_default_ttl_seconds: None,
        password_reset_token_default_ttl_seconds: None,
        recovery_token_max_ttl_seconds: None,
        client_secret_default_expiration_days: None,
        client_secret_max_expiration_days: None,
        private_key_jwt_enabled: None,
        client_jwt_allowed_algs: Some(vec![
            " rs256 ".to_string(),
            "RS256".to_string(),
            String::new(),
        ]),
        client_jwt_require_kid: None,
        jwt_leeway_seconds: None,
        pkjwt_jti_window_seconds: None,
        jose_header_max_len: None,
        jwks_allow_kid_reuse: None,
        jwks_circuit_open_fails: None,
        jwks_circuit_reset_seconds: None,
        jwks_cache_ttl_seconds: None,
        jwks_cache_gc_interval_seconds: None,
        jwks_local_cache_max_entries: None,
        jwks_http_timeout_seconds: None,
        jwks_refresh_skew_seconds: None,
        jwks_shared_state_max_age_seconds: None,
        jwks_max_body_bytes: None,
        jwks_http_retries: None,
        jwt_bearer_allow_client_subject: None,
        jwt_bearer_jti_window_seconds: None,
        request_object_jti_ttl_seconds: None,
        request_object_everparse_runtime_enabled: None,
        jwt_access_tokens_enabled: None,
        jwt_introspection_enabled: None,
        jwt_introspection_exp_seconds: None,
        authorization_details_types_supported: Some(vec![
            " payment_initiation ".to_string(),
            String::new(),
        ]),
        acr_values_supported: Some(vec![" urn:pwd ".to_string(), "urn:mfa".to_string()]),
        default_acr: Some(" urn:mfa ".to_string()),
        local_password_acr: Some("  ".to_string()),
        dcr_require_pkce_for_public: None,
        dcr_require_pkce_for_confidential: None,
        dcr_require_sender_constrained: None,
        dcr_allowed_sender_methods: Some(vec![
            " DPoP ".to_string(),
            String::new(),
        ]),
        ssa_jwt_pem: Some("  ".to_string()),
        ssa_expected_iss: Some("https://issuer.example".to_string()),
        ssa_expected_aud: Some("  ".to_string()),
        ssa_leeway_seconds: None,
        oidc_enabled: None,
        oidc_enable_discovery: None,
        oidc_enable_userinfo: None,
        oidc_enable_logout: None,
        oidc_enable_backchannel_logout: None,
        oidc_logout_session_ttl_seconds: None,
        oidc_backchannel_logout_timeout_seconds: None,
        oidc_require_nonce: None,
        mtls_enabled: None,
        mtls_base_url: Some("  ".to_string()),
        mtls_alias_par_enabled: None,
        federation_outbound_allowed_domains: Some(vec![
            " Example.ORG. ".to_string(),
            "example.org".to_string(),
            String::new(),
        ]),
        upstream_outbound_allowed_domains: Some(vec![
            " Login.Example.ORG. ".to_string(),
            "login.example.org".to_string(),
            String::new(),
        ]),
        federation_entity_cache_ttl_seconds: None,
        federation_trust_chain_cache_ttl_seconds: None,
        federation_cache_max_entries: None,
        crypto_profile: Some(" VERIFIED ".to_string()),
        allowed_signing_algorithms: Some(vec![
            " eddsa ".to_string(),
            "RS256".to_string(),
            String::new(),
        ]),
        allowed_grant_types: Some(vec![
            " authorization_code ".to_string(),
            "REFRESH_TOKEN".to_string(),
            String::new(),
        ]),
        access_token_time_to_live_seconds: None,
        id_token_time_to_live_seconds: None,
        refresh_token_time_to_live_seconds: None,
        authorization_code_time_to_live_seconds: None,
        auth_session_ttl_seconds: None,
        auth_max_sessions: None,
        stepup_challenge_ttl_seconds: None,
        upstream_auth_ttl_seconds: None,
        upstream_logout_relay_ttl_seconds: None,
        upstream_discovery_cache_ttl_seconds: None,
        upstream_discovery_cache_max_entries: None,
        upstream_jwks_cache_ttl_seconds: None,
        upstream_jwks_cache_max_entries: None,
        cleanup_interval_seconds: None,
        runtime_config_monitor_interval_seconds: None,
        comment: None,
        allow_security_downgrade: None,
        reason: None,
    };

    let updated = apply_policy_patch(policy, &patch);
    assert_eq!(updated.client_jwt_allowed_algs, vec!["RS256"]);
    assert_eq!(updated.dcr_allowed_sender_methods, vec!["dpop"]);
    assert_eq!(updated.crypto_profile, "verified");
    assert_eq!(updated.allowed_signing_algorithms, vec!["EdDSA", "RS256"]);
    assert_eq!(
        updated.allowed_grant_types,
        vec!["authorization_code", "refresh_token"]
    );
    assert_eq!(
        updated.authorization_details_types_supported,
        vec!["payment_initiation"]
    );
    assert_eq!(updated.acr_values_supported, vec!["urn:mfa", "urn:pwd"]);
    assert_eq!(updated.default_acr, Some("urn:mfa".to_string()));
    assert_eq!(updated.local_password_acr, None);
    assert_eq!(
        updated.federation_outbound_allowed_domains,
        vec!["example.org"]
    );
    assert_eq!(
        updated.upstream_outbound_allowed_domains,
        vec!["login.example.org"]
    );
    assert_eq!(updated.ssa_jwt_pem, None);
    assert_eq!(
        updated.ssa_expected_iss,
        Some("https://issuer.example".to_string())
    );
    assert_eq!(updated.ssa_expected_aud, None);
    assert_eq!(updated.mtls_base_url, None);
}
