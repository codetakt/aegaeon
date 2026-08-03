#[test]
fn detect_security_downgrade_no_change() {
    let before = base_secure_policy();
    let after = base_secure_policy();
    let downgrades = detect_security_downgrade(&before, &after);
    assert!(downgrades.is_empty(), "no downgrade expected");
}

#[test]
fn detect_security_downgrade_pkce_disabled() {
    let before = base_secure_policy();
    let mut after = base_secure_policy();
    after.pkce_required = false;
    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(downgrades, vec!["pkce_required"]);
}

#[test]
fn detect_security_downgrade_dpop_disabled() {
    let before = base_secure_policy();
    let mut after = base_secure_policy();
    after.dpop_strict = false;
    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(downgrades, vec!["dpop_strict"]);
}

#[test]
fn detect_security_downgrade_multiple_fields() {
    let before = base_secure_policy();
    let mut after = base_secure_policy();
    after.pkce_required = false;
    after.dpop_strict = false;
    after.require_client_auth_token = false;
    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(downgrades.len(), 3);
    assert!(downgrades.contains(&"pkce_required"));
    assert!(downgrades.contains(&"dpop_strict"));
    assert!(downgrades.contains(&"require_client_auth_token"));
}

#[test]
fn detect_security_downgrade_upgrade_not_flagged() {
    let mut before = base_secure_policy();
    before.pkce_required = false;
    let after = base_secure_policy(); // pkce_required=true (upgrade)
    let downgrades = detect_security_downgrade(&before, &after);
    assert!(
        downgrades.is_empty(),
        "upgrade should not trigger downgrade"
    );
}

#[test]
fn detect_security_downgrade_all_client_auth_fields() {
    let before = base_secure_policy();
    let mut after = base_secure_policy();
    after.require_client_auth_par = false;
    after.require_client_auth_introspection = false;
    after.require_client_auth_revocation = false;
    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(downgrades.len(), 3);
    assert!(downgrades.contains(&"require_client_auth_par"));
    assert!(downgrades.contains(&"require_client_auth_introspection"));
    assert!(downgrades.contains(&"require_client_auth_revocation"));
}

#[test]
fn detect_security_downgrade_extended_policy_boundary_fields() {
    let mut before = base_secure_policy();
    before.require_state_parameter = true;
    before.client_jwt_require_kid = true;
    before.dcr_require_pkce_for_public = true;
    before.dcr_require_pkce_for_confidential = true;
    before.dcr_require_sender_constrained = true;
    before.oidc_require_nonce = true;

    let mut after = before.clone();
    after.require_state_parameter = false;
    after.strict_authorize_redirect = false;
    after.client_jwt_require_kid = false;
    after.jwt_bearer_allow_client_subject = true;
    after.dcr_require_pkce_for_public = false;
    after.dcr_require_pkce_for_confidential = false;
    after.dcr_require_sender_constrained = false;
    after.oidc_require_nonce = false;

    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(
        downgrades,
        vec![
            "require_state_parameter",
            "strict_authorize_redirect",
            "client_jwt_require_kid",
            "dcr_require_pkce_for_public",
            "dcr_require_pkce_for_confidential",
            "dcr_require_sender_constrained",
            "oidc_require_nonce",
            "jwt_bearer_allow_client_subject",
        ]
    );
}

#[test]
fn detect_security_downgrade_non_security_field_not_flagged() {
    let before = base_secure_policy();
    let mut after = base_secure_policy();
    after.cleanup_interval_seconds = 75;
    let downgrades = detect_security_downgrade(&before, &after);
    assert!(
        downgrades.is_empty(),
        "non-security field changes should not flag downgrade"
    );
}

#[test]
fn detect_security_downgrade_surface_enablement_fields() {
    let mut before = base_secure_policy();
    before.dcr_enabled = false;
    before.private_key_jwt_enabled = false;
    before.jwt_access_tokens_enabled = false;
    before.jwt_introspection_enabled = false;

    let mut after = before.clone();
    after.dcr_enabled = true;
    after.private_key_jwt_enabled = true;
    after.jwt_access_tokens_enabled = true;
    after.jwt_introspection_enabled = true;

    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(
        downgrades,
        vec![
            "dcr_enabled",
            "private_key_jwt_enabled",
            "jwt_access_tokens_enabled",
            "jwt_introspection_enabled",
        ]
    );
}

#[test]
fn detect_security_downgrade_temporal_and_size_relaxations() {
    let before = base_secure_policy();
    let mut after = before.clone();
    after.jwt_leeway_seconds = before.jwt_leeway_seconds + 1;
    after.pkjwt_jti_window_seconds = before.pkjwt_jti_window_seconds + 1;
    after.jwt_bearer_jti_window_seconds = before.jwt_bearer_jti_window_seconds + 1;
    after.request_object_jti_ttl_seconds = before.request_object_jti_ttl_seconds + 1;
    after.par_expires_in_seconds = before.par_expires_in_seconds + 1;
    after.jose_header_max_len = before.jose_header_max_len + 1;
    after.jwks_max_body_bytes = before.jwks_max_body_bytes + 1;
    after.access_token_time_to_live_seconds = before.access_token_time_to_live_seconds + 1;
    after.auth_max_sessions = before.auth_max_sessions + 1;

    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(
        downgrades,
        vec![
            "par_expires_in_seconds",
            "jwt_leeway_seconds",
            "pkjwt_jti_window_seconds",
            "jwt_bearer_jti_window_seconds",
            "request_object_jti_ttl_seconds",
            "jose_header_max_len",
            "jwks_max_body_bytes",
            "access_token_time_to_live_seconds",
            "auth_max_sessions",
        ]
    );
}

#[test]
fn detect_security_downgrade_resource_capacity_relaxations() {
    let before = base_secure_policy();
    let mut after = before.clone();
    after.jwks_circuit_open_fails = before.jwks_circuit_open_fails + 1;
    after.jwks_http_timeout_seconds = before.jwks_http_timeout_seconds + 1;
    after.jwks_http_retries = before.jwks_http_retries + 1;
    after.jwks_local_cache_max_entries = before.jwks_local_cache_max_entries + 1;
    after.federation_cache_max_entries = before.federation_cache_max_entries + 1;
    after.upstream_discovery_cache_max_entries = before.upstream_discovery_cache_max_entries + 1;
    after.upstream_jwks_cache_max_entries = before.upstream_jwks_cache_max_entries + 1;

    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(
        downgrades,
        vec![
            "jwks_circuit_open_fails",
            "jwks_http_timeout_seconds",
            "jwks_http_retries",
            "jwks_local_cache_max_entries",
            "federation_cache_max_entries",
            "upstream_discovery_cache_max_entries",
            "upstream_jwks_cache_max_entries",
        ]
    );
}

#[test]
fn detect_security_downgrade_protocol_allowlist_expansion() {
    let mut before = base_secure_policy();
    before.allowed_grant_types = vec!["authorization_code".to_string()];
    before.allowed_signing_algorithms = vec!["RS256".to_string()];
    before.client_jwt_allowed_algs = vec!["RS256".to_string()];
    before.dcr_allowed_sender_methods = vec!["dpop".to_string()];

    let mut after = before.clone();
    after.allowed_grant_types = vec![
        "authorization_code".to_string(),
        "client_credentials".to_string(),
    ];
    after.allowed_signing_algorithms = vec!["RS256".to_string(), "EdDSA".to_string()];
    after.client_jwt_allowed_algs = vec!["RS256".to_string(), "PS256".to_string()];
    after.dcr_allowed_sender_methods = vec!["dpop".to_string(), "mtls".to_string()];

    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(
        downgrades,
        vec![
            "allowed_grant_types",
            "allowed_signing_algorithms",
            "client_jwt_allowed_algs",
            "dcr_allowed_sender_methods",
        ]
    );
}

#[test]
fn detect_security_downgrade_protocol_allowlist_replacement() {
    let mut before = base_secure_policy();
    before.allowed_grant_types = vec!["authorization_code".to_string()];
    before.allowed_signing_algorithms = vec!["RS256".to_string()];
    before.client_jwt_allowed_algs = vec!["RS256".to_string()];
    before.dcr_allowed_sender_methods = vec!["dpop".to_string()];

    let mut after = before.clone();
    after.allowed_grant_types = vec!["client_credentials".to_string()];
    after.allowed_signing_algorithms = vec!["EdDSA".to_string()];
    after.client_jwt_allowed_algs = vec!["PS256".to_string()];
    after.dcr_allowed_sender_methods = vec!["mtls".to_string()];

    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(
        downgrades,
        vec![
            "allowed_grant_types",
            "allowed_signing_algorithms",
            "client_jwt_allowed_algs",
            "dcr_allowed_sender_methods",
        ]
    );
}

#[test]
fn detect_security_downgrade_outbound_allowlist_relaxation() {
    let mut before = base_secure_policy();
    before.federation_outbound_allowed_domains = vec!["trust.example".to_string()];
    before.upstream_outbound_allowed_domains = vec!["login.example".to_string()];

    let mut after = before.clone();
    after.federation_outbound_allowed_domains = Vec::new();
    after.upstream_outbound_allowed_domains =
        vec!["login.example".to_string(), "login2.example".to_string()];

    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(
        downgrades,
        vec![
            "federation_outbound_allowed_domains",
            "upstream_outbound_allowed_domains",
        ]
    );
}

#[test]
fn detect_security_downgrade_outbound_allowlist_replacement() {
    let mut before = base_secure_policy();
    before.federation_outbound_allowed_domains = vec!["trust.example".to_string()];
    before.upstream_outbound_allowed_domains = vec!["login.example".to_string()];

    let mut after = before.clone();
    after.federation_outbound_allowed_domains = vec!["other-trust.example".to_string()];
    after.upstream_outbound_allowed_domains = vec!["other-login.example".to_string()];

    let downgrades = detect_security_downgrade(&before, &after);
    assert_eq!(
        downgrades,
        vec![
            "federation_outbound_allowed_domains",
            "upstream_outbound_allowed_domains",
        ]
    );
}
