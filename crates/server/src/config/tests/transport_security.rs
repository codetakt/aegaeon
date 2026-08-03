#[test]
fn dpop_strict_disabled_does_not_change_explicit_sender_constraint() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.sender_constraint = PolicySenderConstraint::None;
    policy.dpop_strict = false;
    must_ok!(cfg.apply_management_policy(&policy), "valid runtime policy");

    assert!(!cfg.dpop_strict);
    assert_eq!(
        cfg.security_policy.sender_constrained,
        SenderConstraint::None
    );
    Ok(())
}

#[test]
fn acr_supported_values_do_not_implicitly_authorize_local_password_acr() -> ConfigTestResult {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.acr_values_supported = vec!["urn:mfa".to_string(), "urn:pwd".to_string()];
    policy.default_acr = None;
    policy.local_password_acr = None;
    must_ok!(cfg.apply_management_policy(&policy), "valid runtime policy");

    assert_eq!(cfg.acr_values_supported, vec!["urn:mfa", "urn:pwd"]);
    assert_eq!(cfg.default_acr, None);
    assert_eq!(cfg.local_password_acr, None);
    Ok(())
}

#[test]
fn local_password_acr_must_be_advertised_when_supported_list_is_present() {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.acr_values_supported = vec!["urn:pwd".to_string()];
    policy.local_password_acr = Some("urn:mfa".to_string());

    let result = panic::catch_unwind(move || cfg.apply_management_policy(&policy));
    assert!(
        matches!(result, Ok(Err(ConfigError::InvalidAcr { configured })) if configured == "urn:mfa"),
        "local password ACR must fail closed when it is outside the supported ACR list"
    );
}

#[test]
fn mtls_sender_constraint_forces_trusted_proxy_boundary() -> ConfigTestResult {
    let base = ServerConfig::default();
    let security_policy = base
        .security_policy
        .with_sender_constraint(SenderConstraint::Mtls);
    let mut transport = base.transport.clone();
    transport.require_tls_proxy = false;
    transport.require_proxy_mtls = false;
    transport.apply_security_policy(&security_policy);
    let cfg = ServerConfig {
        security_policy,
        transport,
        ..base
    };

    assert_eq!(
        cfg.security_policy.sender_constrained,
        SenderConstraint::Mtls
    );
    assert!(
        cfg.transport.require_tls_proxy,
        "mTLS sender binding depends on proxy-provided certificate metadata"
    );
    assert!(
        cfg.transport.require_proxy_mtls,
        "mTLS sender binding must require proxy-provided client certificate metadata"
    );
    Ok(())
}

#[test]
fn proxy_mtls_requirement_forces_tls_proxy_validation() -> ConfigTestResult {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _tls_proxy = EnvVarGuard::new("AEGAEON_REQUIRE_TLS_PROXY", Some("0"));
    let _proxy_mtls = EnvVarGuard::new("AEGAEON_REQUIRE_MTLS_FROM_PROXY", Some("1"));

    let cfg = must_ok!(ServerConfig::try_from_env(), "valid server config");

    assert!(cfg.transport.require_proxy_mtls);
    assert!(
        cfg.transport.require_tls_proxy,
        "client certificate headers are trustworthy only inside the TLS proxy boundary"
    );
    Ok(())
}
