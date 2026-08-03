// ---------------------------------------------------------------
// P1: apply_policy_patch additional edge cases
// ---------------------------------------------------------------

#[test]
fn policy_patch_rejects_federation_op_enablement_input() {
    let request = serde_json::json!({
        "baseConfigurationVersionId": "00000000-0000-0000-0000-000000000000",
        "federationOpEnabled": true
    });
    assert!(serde_json::from_value::<PolicyPatchRequest>(request).is_err());
}

#[test]
fn environment_policy_update_sql_projection_placeholders_are_contiguous() -> ManagementTestResult {
    let sql = super::configuration_documents::UPDATE_ENVIRONMENT_POLICY_SQL;
    let placeholders = policy_update_sql_placeholders(sql)?;
    let expected = (1..=99).collect::<Vec<_>>();
    assert_eq!(
        placeholders, expected,
        "environment policy update SQL placeholders must stay contiguous"
    );

    for (column, placeholder) in [
        ("jwks_local_cache_max_entries", 92usize),
        ("upstream_discovery_cache_max_entries", 93usize),
        ("upstream_jwks_cache_max_entries", 94usize),
        ("activation_token_default_ttl_seconds", 95usize),
        ("password_reset_token_default_ttl_seconds", 96usize),
        ("recovery_token_max_ttl_seconds", 97usize),
        ("client_secret_default_expiration_days", 98usize),
        ("client_secret_max_expiration_days", 99usize),
    ] {
        assert!(
            sql.contains(&format!("{column} = ${placeholder}")),
            "{column} must remain in the explicit lifecycle/capacity bind group"
        );
    }
    Ok(())
}

fn policy_update_sql_placeholders(sql: &str) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    let mut placeholders = std::collections::BTreeSet::new();
    for segment in sql.split('$').skip(1) {
        let digits = segment
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        if digits.is_empty() {
            continue;
        }
        let value = digits
            .parse::<usize>()
            .map_err(|err| std::io::Error::other(format!("invalid SQL placeholder: {err}")))?;
        placeholders.insert(value);
    }
    Ok(placeholders.into_iter().collect())
}

#[test]
fn apply_policy_patch_preserves_untouched_fields() {
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
        client_jwt_allowed_algs: None,
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
        authorization_details_types_supported: None,
        acr_values_supported: None,
        default_acr: None,
        local_password_acr: None,
        dcr_require_pkce_for_public: None,
        dcr_require_pkce_for_confidential: None,
        dcr_require_sender_constrained: None,
        dcr_allowed_sender_methods: None,
        ssa_jwt_pem: None,
        ssa_expected_iss: None,
        ssa_expected_aud: None,
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
        mtls_base_url: None,
        mtls_alias_par_enabled: None,
        federation_outbound_allowed_domains: None,
        upstream_outbound_allowed_domains: None,
        federation_entity_cache_ttl_seconds: None,
        federation_trust_chain_cache_ttl_seconds: None,
        federation_cache_max_entries: None,
        crypto_profile: None,
        allowed_signing_algorithms: None,
        allowed_grant_types: None,
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
    let updated = apply_policy_patch(policy.clone(), &patch);
    assert_eq!(updated.pkce_required, policy.pkce_required);
    assert_eq!(updated.dpop_strict, policy.dpop_strict);
    assert_eq!(
        updated.access_token_time_to_live_seconds,
        policy.access_token_time_to_live_seconds
    );
    assert_eq!(updated.allowed_grant_types, policy.allowed_grant_types);
}

#[test]
fn apply_policy_patch_updates_boolean_fields() {
    let policy = default_policy_document();
    let patch = PolicyPatchRequest {
        base_configuration_version_id: "00000000-0000-0000-0000-000000000000".to_string(),
        pkce_required: Some(false),
        dcr_enabled: Some(true),
        dcr_everparse_runtime_enabled: Some(true),
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
        dpop_strict: Some(false),
        dpop_iat_window_seconds: None,
        dpop_require_nonce: None,
        dpop_nonce_ttl_seconds: None,
        require_pushed_authorization_requests: Some(true),
        par_expires_in_seconds: None,
        device_code_ttl_seconds: Some(900),
        device_code_poll_interval_seconds: Some(10),
        activation_token_default_ttl_seconds: None,
        password_reset_token_default_ttl_seconds: None,
        recovery_token_max_ttl_seconds: None,
        client_secret_default_expiration_days: None,
        client_secret_max_expiration_days: None,
        private_key_jwt_enabled: None,
        client_jwt_allowed_algs: None,
        client_jwt_require_kid: None,
        jwt_leeway_seconds: None,
        pkjwt_jti_window_seconds: None,
        jose_header_max_len: Some(8192),
        jwks_allow_kid_reuse: Some(true),
        jwks_circuit_open_fails: Some(4),
        jwks_circuit_reset_seconds: Some(45),
        jwks_cache_ttl_seconds: Some(450),
        jwks_cache_gc_interval_seconds: Some(700),
        jwks_local_cache_max_entries: Some(321),
        jwks_http_timeout_seconds: Some(9),
        jwks_refresh_skew_seconds: Some(20),
        jwks_shared_state_max_age_seconds: Some(1200),
        jwks_max_body_bytes: Some(128 * 1024),
        jwks_http_retries: Some(3),
        jwt_bearer_allow_client_subject: Some(true),
        jwt_bearer_jti_window_seconds: Some(120),
        request_object_jti_ttl_seconds: None,
        request_object_everparse_runtime_enabled: Some(true),
        jwt_access_tokens_enabled: Some(true),
        jwt_introspection_enabled: Some(true),
        jwt_introspection_exp_seconds: Some(30),
        authorization_details_types_supported: None,
        acr_values_supported: None,
        default_acr: None,
        local_password_acr: None,
        dcr_require_pkce_for_public: None,
        dcr_require_pkce_for_confidential: None,
        dcr_require_sender_constrained: None,
        dcr_allowed_sender_methods: None,
        ssa_jwt_pem: None,
        ssa_expected_iss: None,
        ssa_expected_aud: None,
        ssa_leeway_seconds: None,
        oidc_enabled: Some(true),
        oidc_enable_discovery: None,
        oidc_enable_userinfo: None,
        oidc_enable_logout: None,
        oidc_enable_backchannel_logout: None,
        oidc_logout_session_ttl_seconds: None,
        oidc_backchannel_logout_timeout_seconds: None,
        oidc_require_nonce: None,
        mtls_enabled: None,
        mtls_base_url: None,
        mtls_alias_par_enabled: None,
        federation_outbound_allowed_domains: Some(vec![
            " Example.COM. ".to_string(),
            "example.com".to_string(),
        ]),
        upstream_outbound_allowed_domains: Some(vec![
            " Login.Example.COM. ".to_string(),
            "login.example.com".to_string(),
        ]),
        federation_entity_cache_ttl_seconds: Some(900),
        federation_trust_chain_cache_ttl_seconds: Some(1800),
        federation_cache_max_entries: Some(250),
        crypto_profile: Some("verified".to_string()),
        allowed_signing_algorithms: None,
        allowed_grant_types: None,
        access_token_time_to_live_seconds: Some(7200),
        id_token_time_to_live_seconds: None,
        refresh_token_time_to_live_seconds: None,
        authorization_code_time_to_live_seconds: None,
        auth_session_ttl_seconds: Some(1800),
        auth_max_sessions: Some(123),
        stepup_challenge_ttl_seconds: Some(120),
        upstream_auth_ttl_seconds: Some(180),
        upstream_logout_relay_ttl_seconds: Some(240),
        upstream_discovery_cache_ttl_seconds: Some(600),
        upstream_discovery_cache_max_entries: Some(111),
        upstream_jwks_cache_ttl_seconds: Some(900),
        upstream_jwks_cache_max_entries: Some(222),
        cleanup_interval_seconds: Some(75),
        runtime_config_monitor_interval_seconds: Some(45),
        comment: None,
        allow_security_downgrade: None,
        reason: None,
    };
    let updated = apply_policy_patch(policy, &patch);
    assert!(!updated.pkce_required);
    assert!(updated.dcr_enabled);
    assert!(updated.dcr_everparse_runtime_enabled);
    assert!(!updated.dpop_strict);
    assert!(updated.require_pushed_authorization_requests);
    assert_eq!(updated.device_code_ttl_seconds, 900);
    assert_eq!(updated.device_code_poll_interval_seconds, 10);
    assert!(updated.jwt_bearer_allow_client_subject);
    assert_eq!(updated.jwt_bearer_jti_window_seconds, 120);
    assert!(updated.request_object_everparse_runtime_enabled);
    assert!(updated.jwks_allow_kid_reuse);
    assert_eq!(updated.jwks_circuit_open_fails, 4);
    assert_eq!(updated.jwks_circuit_reset_seconds, 45);
    assert_eq!(updated.jwks_cache_ttl_seconds, 450);
    assert_eq!(updated.jwks_cache_gc_interval_seconds, 700);
    assert_eq!(updated.jwks_local_cache_max_entries, 321);
    assert_eq!(updated.jwks_http_timeout_seconds, 9);
    assert_eq!(updated.jwks_refresh_skew_seconds, 20);
    assert_eq!(updated.jwks_shared_state_max_age_seconds, 1200);
    assert_eq!(updated.jwks_max_body_bytes, 128 * 1024);
    assert_eq!(updated.jwks_http_retries, 3);
    assert_eq!(updated.jose_header_max_len, 8192);
    assert!(updated.jwt_access_tokens_enabled);
    assert!(updated.jwt_introspection_enabled);
    assert_eq!(updated.jwt_introspection_exp_seconds, 30);
    assert!(updated.oidc_enabled);
    assert_eq!(updated.access_token_time_to_live_seconds, 7200);
    assert_eq!(updated.auth_session_ttl_seconds, 1800);
    assert_eq!(updated.auth_max_sessions, 123);
    assert_eq!(updated.stepup_challenge_ttl_seconds, 120);
    assert_eq!(updated.upstream_auth_ttl_seconds, 180);
    assert_eq!(updated.upstream_logout_relay_ttl_seconds, 240);
    assert_eq!(updated.upstream_discovery_cache_ttl_seconds, 600);
    assert_eq!(updated.upstream_discovery_cache_max_entries, 111);
    assert_eq!(updated.upstream_jwks_cache_ttl_seconds, 900);
    assert_eq!(updated.upstream_jwks_cache_max_entries, 222);
    assert_eq!(updated.cleanup_interval_seconds, 75);
    assert_eq!(updated.runtime_config_monitor_interval_seconds, 45);
    assert_eq!(
        updated.federation_outbound_allowed_domains,
        vec!["example.com"]
    );
    assert_eq!(
        updated.upstream_outbound_allowed_domains,
        vec!["login.example.com"]
    );
    assert_eq!(updated.federation_entity_cache_ttl_seconds, 900);
    assert_eq!(updated.federation_trust_chain_cache_ttl_seconds, 1800);
    assert_eq!(updated.federation_cache_max_entries, 250);
    assert_eq!(updated.crypto_profile, "verified");
}

#[test]
fn apply_policy_patch_sets_ssa_fields() {
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
        client_jwt_allowed_algs: None,
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
        authorization_details_types_supported: None,
        acr_values_supported: None,
        default_acr: None,
        local_password_acr: None,
        dcr_require_pkce_for_public: None,
        dcr_require_pkce_for_confidential: None,
        dcr_require_sender_constrained: None,
        dcr_allowed_sender_methods: None,
        ssa_jwt_pem: Some("-----BEGIN PUBLIC KEY-----\nMIIBI...".to_string()),
        ssa_expected_iss: Some("https://trust-anchor.example".to_string()),
        ssa_expected_aud: Some("https://my-as.example".to_string()),
        ssa_leeway_seconds: Some(60),
        oidc_enabled: None,
        oidc_enable_discovery: None,
        oidc_enable_userinfo: None,
        oidc_enable_logout: None,
        oidc_enable_backchannel_logout: None,
        oidc_logout_session_ttl_seconds: None,
        oidc_backchannel_logout_timeout_seconds: None,
        oidc_require_nonce: None,
        mtls_enabled: None,
        mtls_base_url: None,
        mtls_alias_par_enabled: None,
        federation_outbound_allowed_domains: None,
        upstream_outbound_allowed_domains: None,
        federation_entity_cache_ttl_seconds: None,
        federation_trust_chain_cache_ttl_seconds: None,
        federation_cache_max_entries: None,
        crypto_profile: None,
        allowed_signing_algorithms: None,
        allowed_grant_types: None,
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
    assert_eq!(
        updated.ssa_jwt_pem,
        Some("-----BEGIN PUBLIC KEY-----\nMIIBI...".to_string())
    );
    assert_eq!(
        updated.ssa_expected_iss,
        Some("https://trust-anchor.example".to_string())
    );
    assert_eq!(
        updated.ssa_expected_aud,
        Some("https://my-as.example".to_string())
    );
    assert_eq!(updated.ssa_leeway_seconds, 60);
}

// ---------------------------------------------------------------
// P2: Redirect URI validation additional cases
// ---------------------------------------------------------------
