#[test]
fn sender_constraint_is_explicit_management_policy() -> ConfigTestResult {
    let base = ServerConfig::default();
    let mut cfg = ServerConfig {
        security_policy: base
        .security_policy
            .with_sender_constraint(SenderConstraint::None)
            .with_sender_binding_enforcement(false),
        ..base
    };
    let mut policy = management_policy_document();
    policy.dpop_strict = true;
    policy.sender_constraint = PolicySenderConstraint::Dpop;

    must_ok!(cfg.apply_management_policy(&policy), "valid runtime policy");

    assert!(cfg.dpop_strict);
    assert_eq!(
        cfg.security_policy.sender_constrained,
        SenderConstraint::DPoP
    );
    assert!(cfg.security_policy.enforce_sender_binding());
    Ok(())
}

#[test]
fn management_policy_overlay_updates_runtime_security_fields() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.require_state_parameter = false;
    policy.strict_authorize_redirect = false;
    policy.require_client_auth_token = false;
    policy.sender_constraint = PolicySenderConstraint::None;
    policy.require_scope_subset = false;
    policy.require_audience_match = false;
    policy.retain_refresh_chain = false;
    policy.enforce_refresh_sender_binding = false;
    policy.dpop_strict = false;
    policy.dpop_iat_window_seconds = 120;
    policy.dpop_require_nonce = false;
    policy.dpop_nonce_ttl_seconds = 240;
    policy.jwt_leeway_seconds = 30;
    policy.allowed_grant_types = vec![
        "authorization_code".to_string(),
        "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
    ];
    policy.access_token_time_to_live_seconds = 900;
    policy.refresh_token_time_to_live_seconds = 7200;
    policy.authorization_code_time_to_live_seconds = 240;
    policy.par_expires_in_seconds = 120;
    policy.pkjwt_jti_window_seconds = 180;
    policy.jwt_bearer_allow_client_subject = true;
    policy.jwt_bearer_jti_window_seconds = 240;
    policy.request_object_jti_ttl_seconds = 300;
    policy.jwt_access_tokens_enabled = true;
    policy.jwt_introspection_enabled = true;
    policy.jwt_introspection_exp_seconds = 30;
    policy.authorization_details_types_supported =
        vec![" payment_initiation ".to_string(), String::new()];
    policy.acr_values_supported = vec![" urn:pwd ".to_string(), "urn:mfa".to_string()];
    policy.default_acr = Some(" urn:mfa ".to_string());
    policy.local_password_acr = Some("urn:pwd".to_string());
    policy.stepup_challenge_ttl_seconds = 120;
    policy.upstream_auth_ttl_seconds = 180;
    policy.upstream_logout_relay_ttl_seconds = 240;
    policy.upstream_outbound_allowed_domains = vec![
        " Login.Example.COM. ".to_string(),
        "login.example.com".to_string(),
    ];
    policy.oidc_enabled = true;
    policy.crypto_profile = "verified".to_string();

    must_ok!(cfg.apply_management_policy(&policy), "valid policy overlay");

    assert!(!cfg.require_state);
    assert!(!cfg.strict_authorize_redirect);
    assert!(!cfg.require_client_auth_token);
    assert!(!cfg.dpop_strict);
    assert_eq!(cfg.dpop_iat_window_secs, 120);
    assert!(!cfg.require_dpop_nonce);
    assert_eq!(cfg.dpop_nonce_ttl_secs, 240);
    assert_eq!(cfg.jwt_leeway_secs, 30);
    assert_eq!(cfg.access_token_ttl_secs, 900);
    assert_eq!(cfg.refresh_token_ttl_secs, 7200);
    assert_eq!(cfg.authorization_code_ttl_secs, 240);
    assert_eq!(cfg.par_expires_in_secs, 120);
    assert_eq!(cfg.pkjwt_jti_window_secs, 180);
    assert!(cfg.allow_jwt_bearer_client_subject);
    assert_eq!(cfg.jwt_bearer_jti_window_secs, 240);
    assert_eq!(cfg.request_object_jti_ttl_secs, 300);
    assert!(cfg.enable_jwt_access_tokens);
    assert!(cfg.enable_jwt_introspection);
    assert_eq!(cfg.jwt_introspection_exp_secs, 30);
    assert_eq!(
        cfg.authorization_details_types_supported,
        vec!["payment_initiation"]
    );
    assert_eq!(cfg.acr_values_supported, vec!["urn:pwd", "urn:mfa"]);
    assert_eq!(cfg.default_acr, Some("urn:mfa".to_string()));
    assert_eq!(cfg.local_password_acr, Some("urn:pwd".to_string()));
    assert_eq!(cfg.stepup_challenge_ttl_secs, 120);
    assert_eq!(cfg.upstream_auth_ttl_secs, 180);
    assert_eq!(cfg.upstream_logout_relay_ttl_secs, 240);
    assert_eq!(
        cfg.upstream_outbound_allowed_domains,
        vec!["login.example.com"]
    );
    assert_eq!(
        cfg.crypto_profile,
        aegaeon_jose::algorithms::CryptoProfile::Verified
    );
    assert_eq!(
        cfg.security_policy.sender_constrained,
        SenderConstraint::None
    );
    assert!(!cfg.security_policy.require_scope_subset());
    assert!(!cfg.security_policy.require_audience_match());
    assert!(!cfg.security_policy.retain_refresh_chain());
    assert!(!cfg.security_policy.enforce_sender_binding());
    assert!(cfg.enable_token_exchange);
    assert_eq!(
        cfg.allowed_grant_types,
        vec![
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ]
    );
    Ok(())
}

#[test]
fn management_policy_overlay_rejects_invalid_runtime_values() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.dpop_iat_window_seconds = 0;

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid policy must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "dpop_iat_window_seconds"
    ));
    Ok(())
}

#[test]
fn management_policy_overlay_rejects_unimplemented_dcr_sender_method() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.dcr_allowed_sender_methods = vec!["mtls".to_string()];

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "unimplemented DCR sender method must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "dcr_allowed_sender_methods"
    ));
    Ok(())
}

#[test]
fn management_policy_overlay_rejects_unsupported_grant_type() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.allowed_grant_types = vec!["authorization_code".to_string(), "urn:custom".to_string()];

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "unknown grant type must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == "allowed_grant_types" && reason.contains("unsupported grant type")
    ));
    Ok(())
}

#[test]
fn management_policy_overlay_rejects_unadvertised_local_password_acr() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.acr_values_supported = vec!["urn:pwd".to_string()];
    policy.local_password_acr = Some("urn:mfa".to_string());

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "unsupported local password ACR must fail closed",
    );

    assert!(matches!(err, ConfigError::InvalidAcr { configured } if configured == "urn:mfa"));
    Ok(())
}

#[test]
fn management_policy_overlay_rejects_unbounded_authorization_request_ttls() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.par_expires_in_seconds = must_ok!(
        (MAX_PAR_EXPIRES_IN_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid PAR TTL must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "par_expires_in_seconds"
    ));

    let mut policy = management_policy_document();
    policy.authorization_code_time_to_live_seconds = must_ok!(
        (MAX_AUTHORIZATION_CODE_TTL_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid authorization-code TTL must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. }
            if key == "authorization_code_time_to_live_seconds"
    ));

    let mut policy = management_policy_document();
    policy.auth_session_ttl_seconds = must_ok!(
        (MAX_AUTH_SESSION_TTL_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid auth session TTL must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "auth_session_ttl_seconds"
    ));

    let mut policy = management_policy_document();
    policy.auth_max_sessions = must_ok!(
        u32::try_from(MAX_AUTH_MAX_SESSIONS + 1),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid auth session capacity must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "auth_max_sessions"
    ));

    let mut policy = management_policy_document();
    policy.dpop_nonce_ttl_seconds = must_ok!(
        (MAX_DPOP_NONCE_TTL_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid DPoP nonce TTL must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "dpop_nonce_ttl_seconds"
    ));

    let mut policy = management_policy_document();
    policy.stepup_challenge_ttl_seconds = must_ok!(
        (MAX_STEPUP_CHALLENGE_TTL_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid step-up challenge TTL must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "stepup_challenge_ttl_seconds"
    ));

    let mut policy = management_policy_document();
    policy.jwt_introspection_exp_seconds = must_ok!(
        (MAX_JWT_INTROSPECTION_EXP_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid JWT introspection response lifetime must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "jwt_introspection_exp_seconds"
    ));

    let mut policy = management_policy_document();
    policy.upstream_auth_ttl_seconds = must_ok!(
        (MAX_UPSTREAM_AUTH_TTL_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid upstream auth TTL must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "upstream_auth_ttl_seconds"
    ));

    let mut policy = management_policy_document();
    policy.upstream_logout_relay_ttl_seconds = must_ok!(
        (MAX_UPSTREAM_LOGOUT_RELAY_TTL_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid upstream logout relay TTL must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. }
            if key == "upstream_logout_relay_ttl_seconds"
    ));

    let mut policy = management_policy_document();
    policy.runtime_config_monitor_interval_seconds = 0;

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid runtime config monitor interval must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. }
            if key == "runtime_config_monitor_interval_seconds"
    ));

    let mut policy = management_policy_document();
    policy.pkjwt_jti_window_seconds = must_ok!(
        u32::try_from(MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS + 1),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid private-key-jwt replay window must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "pkjwt_jti_window_seconds"
    ));

    let mut policy = management_policy_document();
    policy.jwt_bearer_jti_window_seconds = must_ok!(
        u32::try_from(MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS + 1),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid JWT bearer replay window must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "jwt_bearer_jti_window_seconds"
    ));

    let mut policy = management_policy_document();
    policy.request_object_jti_ttl_seconds = must_ok!(
        (MAX_REQUEST_OBJECT_JTI_TTL_SECS + 1).try_into(),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid request-object replay window must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. }
            if key == "request_object_jti_ttl_seconds"
    ));

    let mut policy = management_policy_document();
    policy.jose_header_max_len =
        must_ok!((MAX_JOSE_HEADER_LEN + 1).try_into(), "test value fits u32");

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid JOSE header length must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "jose_header_max_len"
    ));

    let mut policy = management_policy_document();
    policy.ssa_leeway_seconds = must_ok!(
        u32::try_from(MAX_SSA_LEEWAY_SECS + 1),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid SSA leeway must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "ssa_leeway_seconds"
    ));

    let mut policy = management_policy_document();
    policy.oidc_logout_session_ttl_seconds = must_ok!(
        u32::try_from(crate::oidc::session::MAX_LOGOUT_SESSION_TTL_SECS + 1),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid OIDC logout session TTL must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "oidc_logout_session_ttl_seconds"
    ));

    let mut policy = management_policy_document();
    policy.oidc_backchannel_logout_timeout_seconds = must_ok!(
        u32::try_from(crate::oidc::config::MAX_BACKCHANNEL_LOGOUT_TIMEOUT_SECS + 1),
        "test value fits u32",
    );

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid OIDC back-channel logout timeout must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. }
            if key == "oidc_backchannel_logout_timeout_seconds"
    ));
    Ok(())
}

#[test]
fn management_policy_overlay_rejects_invalid_ssa_public_key_pem() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.ssa_jwt_pem = Some("not a PEM public key".to_string());

    let err = must_err!(
        cfg.apply_management_policy(&policy),
        "invalid software-statement public key PEM must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "ssa_jwt_pem"
    ));
    Ok(())
}

#[test]
fn management_policy_overlay_accepts_valid_ssa_public_key_pem() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.ssa_jwt_pem = Some(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa2048-public.pem"
        ))
        .to_string(),
    );

    must_ok!(
        cfg.apply_management_policy(&policy),
        "valid software-statement public key PEM should be accepted",
    );
    Ok(())
}
