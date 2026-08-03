// ── URL Construction ─────────────────────────────────────────────

fn fetcher_test_authority_config(entity_id: &str) -> EntityStatement {
    sample_entity_config(entity_id, 1_700_000_000)
}

#[test]
fn entity_configuration_url_basic() {
    assert_eq!(
        must_ok(entity_configuration_url("https://op.example.com")),
        "https://op.example.com/.well-known/openid-federation"
    );
}

#[test]
fn entity_configuration_url_trailing_slash() {
    assert_eq!(
        must_ok(entity_configuration_url("https://op.example.com/")),
        "https://op.example.com/.well-known/openid-federation"
    );
}

#[test]
fn entity_configuration_url_preserves_base_path() {
    assert_eq!(
        must_ok(entity_configuration_url("https://op.example.com/tenant/a")),
        "https://op.example.com/tenant/a/.well-known/openid-federation"
    );
}

#[test]
fn subordinate_statement_url_basic() {
    let authority = fetcher_test_authority_config("https://ta.example.com");
    assert_eq!(
            must_ok(subordinate_statement_url(
                "https://ta.example.com",
                &authority,
                "https://rp.example.com"
            )),
            "https://ta.example.com/.well-known/openid-federation/fetch?sub=https%3A%2F%2Frp.example.com"
        );
}

#[test]
fn subordinate_statement_url_preserves_base_path() {
    let authority = fetcher_test_authority_config("https://ta.example.com/tenant/a");
    assert_eq!(
            must_ok(subordinate_statement_url(
                "https://ta.example.com/tenant/a",
                &authority,
                "https://rp.example.com"
            )),
            "https://ta.example.com/tenant/a/.well-known/openid-federation/fetch?sub=https%3A%2F%2Frp.example.com"
        );
}

// ── SSRF Protection (C-3) ───────────────────────────────────────

#[test]
fn entity_configuration_url_rejects_http() {
    let err = must_err(entity_configuration_url("http://evil.example.com"));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn entity_configuration_url_rejects_ftp() {
    let err = must_err(entity_configuration_url("ftp://evil.example.com"));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn entity_configuration_url_rejects_invalid() {
    let err = must_err(entity_configuration_url("not-a-url"));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn entity_configuration_url_invalid_error_does_not_echo_input() {
    let raw = "not-a-url-with-secret-token";
    let err = must_err(entity_configuration_url(raw));
    assert!(!err.to_string().contains(raw));
    assert!(!err.to_string().contains("secret-token"));
}

#[test]
fn entity_configuration_url_rejects_query_fragment_and_userinfo() {
    for entity_id in [
        "https://op.example.com?x=1",
        "https://op.example.com#fragment",
        "https://user@op.example.com",
        "https://user:password@op.example.com",
    ] {
        let err = must_err(entity_configuration_url(entity_id));
        assert!(matches!(err, FederationError::Validation(_)));
    }
}

#[test]
fn entity_configuration_url_rejects_non_routable_literal_hosts() {
    for entity_id in [
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://[fc00::1]",
    ] {
        let err = must_err(entity_configuration_url(entity_id));
        assert!(matches!(err, FederationError::Validation(_)));
    }
}

#[test]
fn subordinate_statement_url_rejects_http() {
    let authority = fetcher_test_authority_config("http://evil.example.com");
    let err = must_err(subordinate_statement_url(
        "http://evil.example.com",
        &authority,
        "https://sub.example.com",
    ));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn subordinate_statement_url_encodes_sub_parameter() {
    // Verify that special characters in sub are properly encoded
    let authority = fetcher_test_authority_config("https://ta.example.com");
    let url = subordinate_statement_url(
        "https://ta.example.com",
        &authority,
        "https://rp.example.com/path?q=1&r=2",
    );
    let url = must_ok(url);
    // The sub parameter should be percent-encoded
    assert!(url.starts_with("https://ta.example.com/.well-known/openid-federation/fetch?sub="));
    assert!(!url.contains("&r=2")); // '&' should be encoded, not raw
}

#[test]
fn subordinate_statement_url_rejects_query_fragment_and_userinfo_authorities() {
    for authority_id in [
        "https://ta.example.com?x=1",
        "https://ta.example.com#fragment",
        "https://user@ta.example.com",
        "https://user:password@ta.example.com",
    ] {
        let authority = fetcher_test_authority_config(authority_id);
        let err = must_err(subordinate_statement_url(
            authority_id,
            &authority,
            "https://sub.example.com",
        ));
        assert!(matches!(err, FederationError::Validation(_)));
    }
}

#[test]
fn validate_entity_url_rejects_no_host() {
    let err = must_err(validate_entity_url("https://"));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn domain_allowlist_rejects_unlisted() {
    let fetcher = must_ok(HttpFederationFetcher::try_with_allowed_domains(vec![
        "trusted.example.com".to_string(),
    ]));
    let err = must_err(fetcher.validate_domain("https://evil.example.com"));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn domain_allowlist_allows_listed() {
    let fetcher = must_ok(HttpFederationFetcher::try_with_allowed_domains(vec![
        "trusted.example.com".to_string(),
    ]));
    assert!(fetcher
        .validate_domain("https://trusted.example.com")
        .is_ok());
}

#[test]
fn domain_allowlist_allows_subdomain() {
    let fetcher = must_ok(HttpFederationFetcher::try_with_allowed_domains(vec![
        "example.com".to_string(),
    ]));
    assert!(fetcher.validate_domain("https://sub.example.com").is_ok());
}

#[test]
fn domain_allowlist_matches_case_insensitively() {
    assert!(host_matches_allowlist(
        "Sub.Example.COM",
        &["EXAMPLE.com".to_string()]
    ));
}

#[test]
fn domain_allowlist_normalizes_domains() {
    let fetcher = must_ok(HttpFederationFetcher::try_with_allowed_domains(vec![
        " Example.COM. ".to_string(),
    ]));
    assert!(fetcher.validate_domain("https://sub.example.com.").is_ok());
}

#[test]
fn domain_allowlist_rejects_url_syntax() {
    let err = must_err(HttpFederationFetcher::try_with_allowed_domains(vec![
        "https://example.com".to_string(),
    ]));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn domain_allowlist_none_allows_all() {
    let fetcher = must_ok(HttpFederationFetcher::try_new());
    assert!(fetcher.validate_domain("https://any.example.com").is_ok());
}

#[test]
fn federation_fetch_status_rejects_non_success() {
    let err = must_err(ensure_fetch_status_success(reqwest::StatusCode::NOT_FOUND));
    assert!(matches!(err, FederationError::Fetch(_)));
}

#[test]
fn federation_fetch_status_accepts_success() {
    assert!(ensure_fetch_status_success(reqwest::StatusCode::OK).is_ok());
}
