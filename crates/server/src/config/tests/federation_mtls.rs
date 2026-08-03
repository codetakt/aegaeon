#[test]
fn mtls_base_url_must_use_safe_public_url_policy() {
    let mut cfg = ServerConfig::default();
    let mut policy = management_policy_document();
    policy.mtls_base_url = Some("http://mtls.auth.example.com".to_string());

    let result = panic::catch_unwind(move || cfg.apply_management_policy(&policy));

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, .. })) if key == "mtls_base_url"
    ));
}
