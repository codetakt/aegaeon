
// ---------------------------------------------------------------
// P1: ManagementConfig
// ---------------------------------------------------------------

#[test]
fn management_config_bootstrap_token_sha256_none_by_default() {
    let cfg = test_management_config();
    assert!(cfg.bootstrap_token_sha256().is_none());
}

#[test]
fn management_config_bootstrap_token_sha256_set() -> TestResult {
    let cfg = ManagementConfig {
        allowed_origins: vec![],
        issuer_base_domain: "example.com".to_string(),
        cookie_secure: false,
        session_ttl_secs: 60,
        max_sessions: DEFAULT_MAX_SESSIONS,
        bootstrap_token_sha256: Some(sha256_array(b"my-secret-token")),
    };
    assert!(cfg.bootstrap_token_sha256().is_some());
    let hash = cfg
        .bootstrap_token_sha256()
        .ok_or_else(|| io::Error::other("missing bootstrap token hash"))?;
    assert_eq!(hash, &sha256_array(b"my-secret-token"));
    Ok(())
}

#[test]
fn management_config_control_plane_policy_overrides_session_limits() -> TestResult {
    let cfg = test_management_config().with_control_plane_policy(ControlPlanePolicy {
        session_ttl_secs: 7_200,
        max_sessions: 512,
        ..ControlPlanePolicy::default()
    })?;

    assert_eq!(cfg.session_ttl_secs, 7_200);
    assert_eq!(cfg.max_sessions, 512);
    Ok(())
}

#[test]
fn management_config_control_plane_policy_overrides_origin_and_domain() -> TestResult {
    let cfg = test_management_config().with_control_plane_policy(ControlPlanePolicy {
        allowed_origins: vec![
            " https://ADMIN.example.com/ ".to_string(),
            "https://ops.example.com:8443".to_string(),
        ],
        issuer_base_domain: "Issuers.Example.COM".to_string(),
        ..ControlPlanePolicy::default()
    })?;

    assert_eq!(
        cfg.allowed_origins,
        vec![
            "https://admin.example.com".to_string(),
            "https://ops.example.com:8443".to_string()
        ]
    );
    assert_eq!(cfg.issuer_base_domain, "issuers.example.com");
    Ok(())
}

#[test]
fn management_config_control_plane_policy_rejects_invalid_ttl() -> TestResult {
    let err = must_err!(
        test_management_config().with_control_plane_policy(ControlPlanePolicy {
            session_ttl_secs: MAX_SESSION_TTL_SECS + 1,
            max_sessions: DEFAULT_MAX_SESSIONS,
            ..ControlPlanePolicy::default()
        }),
        "invalid DB-backed management session TTL must fail closed"
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. }
            if key == "management_session_ttl_seconds"
    ));
    Ok(())
}

#[test]
fn management_config_control_plane_policy_rejects_invalid_capacity() -> TestResult {
    let err = must_err!(
        test_management_config().with_control_plane_policy(ControlPlanePolicy {
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            max_sessions: MAX_MANAGEMENT_MAX_SESSIONS + 1,
            ..ControlPlanePolicy::default()
        }),
        "invalid DB-backed management session capacity must fail closed"
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. } if key == "management_max_sessions"
    ));
    Ok(())
}

#[test]
fn management_config_control_plane_policy_rejects_invalid_origin() -> TestResult {
    let err = must_err!(
        test_management_config().with_control_plane_policy(ControlPlanePolicy {
            allowed_origins: vec!["http://admin.example.com".to_string()],
            ..ControlPlanePolicy::default()
        }),
        "invalid DB-backed management origin must fail closed"
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "management_allowed_origins"
    ));
    Ok(())
}

#[test]
fn management_config_control_plane_policy_rejects_invalid_issuer_base_domain() -> TestResult {
    let err = must_err!(
        test_management_config().with_control_plane_policy(ControlPlanePolicy {
            issuer_base_domain: "localhost".to_string(),
            ..ControlPlanePolicy::default()
        }),
        "invalid DB-backed management issuer base domain must fail closed"
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == "management_issuer_base_domain"
    ));
    Ok(())
}

#[test]
fn management_database_bootstrap_ignores_session_limit_environment() -> TestResult {
    let _guard = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|_| "server env guard".to_string())?;
    let _allowed_origins = EnvVarGuard::set("AEGAEON_MANAGEMENT_ALLOWED_ORIGINS", "not-a-url");
    let _issuer_domain = EnvVarGuard::set("AEGAEON_MANAGEMENT_ISSUER_BASE_DOMAIN", "localhost");
    let _cookie_secure = EnvVarGuard::unset("AEGAEON_MANAGEMENT_COOKIE_SECURE");
    let _bootstrap = EnvVarGuard::unset("AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN");
    let _session_ttl = EnvVarGuard::set("AEGAEON_MANAGEMENT_SESSION_TTL_SECS", "0");
    let _max_sessions = EnvVarGuard::set("AEGAEON_MANAGEMENT_MAX_SESSIONS", "0");

    let cfg = must_ok!(
        ManagementConfig::try_from_system_bootstrap_env(),
        "database-authoritative bootstrap must not parse session limit env"
    );

    assert_eq!(cfg.session_ttl_secs, DEFAULT_SESSION_TTL_SECS);
    assert_eq!(cfg.max_sessions, DEFAULT_MAX_SESSIONS);
    assert!(cfg.allowed_origins.is_empty());
    assert_eq!(cfg.issuer_base_domain, "aegaeon.cloud");
    assert!(cfg.cookie_secure);
    Ok(())
}

#[test]
fn management_database_bootstrap_rejects_legacy_cookie_secure_environment() -> TestResult {
    let _guard = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|_| "server env guard".to_string())?;
    let _cookie_secure = EnvVarGuard::set("AEGAEON_MANAGEMENT_COOKIE_SECURE", "0");
    let _bootstrap = EnvVarGuard::unset("AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN");

    let err = must_err!(
        ManagementConfig::try_from_system_bootstrap_env(),
        "legacy management cookie Secure override must fail closed"
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_MANAGEMENT_COOKIE_SECURE"
                && reason.contains("always Secure")
    ));
    Ok(())
}

#[test]
fn normalize_management_allowed_origin_accepts_https_origin_only() -> TestResult {
    assert_eq!(
        normalize_management_allowed_origin(" https://ADMIN.example.com/ ")
            .map_err(io::Error::other)?,
        "https://admin.example.com"
    );
    assert_eq!(
        normalize_management_allowed_origin("https://admin.example.com:8443")
            .map_err(io::Error::other)?,
        "https://admin.example.com:8443"
    );
    Ok(())
}

#[test]
fn normalize_management_allowed_origin_rejects_non_origin_values() {
    for origin in [
        "",
        "not-a-url",
        "http://admin.example.com",
        "https://",
        "https://user@admin.example.com",
        "https://admin.example.com/path",
        "https://admin.example.com?x=1",
        "https://admin.example.com#fragment",
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://[fc00::1]",
    ] {
        assert!(
            normalize_management_allowed_origin(origin).is_err(),
            "invalid management origin must be rejected: {origin:?}"
        );
    }
}

#[test]
fn management_cors_allowed_origins_accepts_valid_config() -> TestResult {
    let cfg = test_management_config();
    let origins = management_cors_allowed_origins(&cfg)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("expected configured CORS origins"))?;

    assert_eq!(
        origins,
        vec![HeaderValue::from_static("https://admin.example.com")]
    );
    Ok(())
}

#[test]
fn management_cors_allowed_origins_rejects_invalid_internal_state() {
    let mut cfg = test_management_config();
    cfg.allowed_origins = vec!["https://admin.example.com\nx-invalid: true".to_string()];

    assert!(management_cors_allowed_origins(&cfg).is_err());
}

#[test]
fn management_login_rate_limit_keys_cover_ip_principal_and_pair_buckets() -> TestResult {
    let remote: SocketAddr = "198.51.100.23:9443".parse()?;
    let keys = management_login_rate_limit_keys(remote, " Owner@Example.COM ");
    let normalized_keys = management_login_rate_limit_keys(remote, "owner@example.com");

    assert_eq!(keys, normalized_keys);
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0], "management-login:ip:198.51.100.23");
    assert!(keys[1].starts_with("management-login:principal:"));
    assert!(keys[2].starts_with("management-login:pair:198.51.100.23:"));
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[1], keys[2]);
    Ok(())
}

#[test]
fn management_login_rate_limit_allows_rejects_after_any_bucket_exhausts() -> TestResult {
    let limiter = VerificationRateLimiter::new_process_local_for_tests();
    let remote: SocketAddr = "198.51.100.23:9443".parse()?;
    let keys = management_login_rate_limit_keys(remote, "owner@example.com");

    for _ in 0..10 {
        assert!(management_login_rate_limit_allows(&limiter, &keys).map_err(io::Error::other)?);
    }
    assert!(!management_login_rate_limit_allows(&limiter, &keys).map_err(io::Error::other)?);
    Ok(())
}

#[test]
fn management_login_rate_limit_allows_does_not_partially_consume_buckets() -> TestResult {
    let limiter = VerificationRateLimiter::new_process_local_for_tests();
    let remote: SocketAddr = "198.51.100.23:9443".parse()?;
    let keys = management_login_rate_limit_keys(remote, "owner@example.com");

    for _ in 0..10 {
        assert!(must_ok!(limiter.try_check(&keys[1]), "rate limiter"));
    }
    assert!(!management_login_rate_limit_allows(&limiter, &keys).map_err(io::Error::other)?);

    for _ in 0..10 {
        assert!(
            must_ok!(limiter.try_check(&keys[0]), "rate limiter"),
            "failed composite admission must not consume the IP bucket"
        );
    }
    assert!(!must_ok!(limiter.try_check(&keys[0]), "rate limiter"));
    Ok(())
}

#[test]
fn enforce_bootstrap_token_rejects_unconfigured_token() -> TestResult {
    let cfg = test_management_config();
    let response = must_err!(
        enforce_bootstrap_token(&cfg, Some("anything"), "req-1"),
        "bootstrap must fail closed when token is not configured"
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[test]
fn enforce_bootstrap_token_accepts_matching_token() {
    let cfg = ManagementConfig {
        allowed_origins: vec![],
        issuer_base_domain: "example.com".to_string(),
        cookie_secure: false,
        session_ttl_secs: 60,
        max_sessions: DEFAULT_MAX_SESSIONS,
        bootstrap_token_sha256: Some(sha256_array(b"my-secret-token")),
    };
    assert!(enforce_bootstrap_token(&cfg, Some("my-secret-token"), "req-1").is_ok());
}
