
#[test]
fn validate_upstream_discovery_accepts_valid_metadata() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let discovery = base_discovery(&issuer)?;
    let profile = base_profile();
    assert!(validate_upstream_discovery(&discovery, &issuer, &profile, "none", &[]).is_ok());
    Ok(())
}

#[test]
fn validate_upstream_discovery_rejects_endpoint_outside_allowlist() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let discovery = base_discovery(&issuer)?;
    let profile = base_profile();
    let err = require_err(
        validate_upstream_discovery(
            &discovery,
            &issuer,
            &profile,
            "none",
            &["login.example".to_string()],
        ),
        "upstream endpoint outside allowlist should be rejected",
    )?;
    assert!(err.contains("allowlist"));
    Ok(())
}

#[test]
fn normalize_issuer_keeps_ipv6_authority_bracketed() -> TestResult {
    assert_eq!(
        normalize_issuer("https://[::1]:8443/upstream/"),
        Some("https://[::1]:8443/upstream".to_string())
    );
    assert_eq!(
        normalize_issuer("https://[::1]:443"),
        Some("https://[::1]/".to_string())
    );
    Ok(())
}

#[test]
fn build_upstream_logout_session_extracts_standard_session_hint() -> TestResult {
    let issuer = "https://issuer.example";
    let mut discovery = base_discovery(issuer)?;
    discovery.end_session_endpoint = Some("https://issuer.example/logout".to_string());
    let id_token = logout_test_id_token(issuer);
    let policy = UpstreamLogoutPolicy {
        back_channel: false,
        session_hint_claim: Some("sid".to_string()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
    };

    let request = logout_test_request(issuer, policy.clone());

    let session = build_upstream_logout_session(
        Some(&policy),
        issuer,
        &discovery,
        &id_token,
        &request,
        &[],
    )
    .ok_or_else(|| "session".to_string())?;

    assert_eq!(session.issuer, issuer);
    assert_eq!(
        session.end_session_endpoint.as_deref(),
        Some("https://issuer.example/logout")
    );
    assert_eq!(session.session_hint_value.as_deref(), Some("sid-123"));
    Ok(())
}

#[test]
fn build_upstream_logout_session_extracts_additional_claim_session_hint() -> TestResult {
    let issuer = "https://issuer.example";
    let discovery = base_discovery(issuer)?;
    let id_token = logout_test_id_token(issuer);
    let policy = UpstreamLogoutPolicy {
        back_channel: true,
        session_hint_claim: Some("email".to_string()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
    };

    let request = logout_test_request(issuer, policy.clone());
    let session = build_upstream_logout_session(
        Some(&policy),
        issuer,
        &discovery,
        &id_token,
        &request,
        &[],
    )
    .ok_or_else(|| "session".to_string())?;

    assert_eq!(
        session.session_hint_value.as_deref(),
        Some("user@example.com")
    );
    assert!(session.end_session_endpoint.is_none());
    Ok(())
}

#[test]
fn build_upstream_logout_redirect_target_appends_logout_hint() -> TestResult {
    let session = UpstreamLogoutSession {
        issuer: "https://issuer.example".to_string(),
        end_session_endpoint: Some("https://issuer.example/logout".to_string()),
        back_channel: false,
        session_hint_claim: Some("sid".to_string()),
        session_hint_value: Some("sid-123".to_string()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        team_id: None,
        tenant_id: None,
        environment_id: None,
        connection_id: None,
    };

    let redirect =
        build_upstream_logout_redirect_target(&session, &[]).ok_or_else(|| "redirect".to_string())?;

    assert_eq!(
        redirect,
        "https://issuer.example/logout?logout_hint=sid-123"
    );
    Ok(())
}

#[test]
fn build_upstream_logout_redirect_target_suppresses_backchannel_policy() {
    let session = UpstreamLogoutSession {
        issuer: "https://issuer.example".to_string(),
        end_session_endpoint: Some("https://issuer.example/logout".to_string()),
        back_channel: true,
        session_hint_claim: Some("sid".to_string()),
        session_hint_value: Some("sid-123".to_string()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        team_id: None,
        tenant_id: None,
        environment_id: None,
        connection_id: None,
    };

    assert!(build_upstream_logout_redirect_target(&session, &[]).is_none());
}

#[test]
fn build_upstream_logout_redirect_target_rejects_preexisting_query_or_fragment() {
    for endpoint in [
        "https://issuer.example/logout?state=attacker",
        "https://issuer.example/logout#fragment",
    ] {
        let session = UpstreamLogoutSession {
            issuer: "https://issuer.example".to_string(),
            end_session_endpoint: Some(endpoint.to_string()),
            back_channel: false,
            session_hint_claim: Some("sid".to_string()),
            session_hint_value: Some("sid-123".to_string()),
            recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
            team_id: None,
            tenant_id: None,
            environment_id: None,
            connection_id: None,
        };

        assert!(build_upstream_logout_redirect_target(&session, &[]).is_none());
    }
}

#[test]
fn build_upstream_logout_redirect_target_rechecks_current_allowlist() {
    let session = UpstreamLogoutSession {
        issuer: "https://issuer.example".to_string(),
        end_session_endpoint: Some("https://logout.example/logout".to_string()),
        back_channel: false,
        session_hint_claim: Some("sid".to_string()),
        session_hint_value: Some("sid-123".to_string()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        team_id: None,
        tenant_id: None,
        environment_id: None,
        connection_id: None,
    };

    assert!(build_upstream_logout_redirect_target(
        &session,
        &["issuer.example".to_string()]
    )
    .is_none());
}

#[test]
fn local_logout_redirect_target_prefers_upstream_logout_when_available() {
    let session = AuthSession {
        user_id: "user-1".to_string(),
        created_at_epoch_secs: 1,
        auth_time_epoch_secs: 1,
        expires_at_epoch_secs: 2,
        acr: None,
        claim_release_policy: None,
        upstream_logout: Some(UpstreamLogoutSession {
            issuer: "https://issuer.example".to_string(),
            end_session_endpoint: Some("https://issuer.example/logout".to_string()),
            back_channel: false,
            session_hint_claim: Some("sid".to_string()),
            session_hint_value: Some("sid-123".to_string()),
            recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
            team_id: None,
            tenant_id: None,
            environment_id: None,
            connection_id: None,
        }),
    };

    assert_eq!(
        local_logout_redirect_target(Some(&session)),
        "https://issuer.example/logout?logout_hint=sid-123"
    );
}

#[test]
fn local_logout_redirect_target_falls_back_to_login_without_upstream_context() {
    let session = AuthSession {
        user_id: "user-1".to_string(),
        created_at_epoch_secs: 1,
        auth_time_epoch_secs: 1,
        expires_at_epoch_secs: 2,
        acr: None,
        claim_release_policy: None,
        upstream_logout: None,
    };

    assert_eq!(local_logout_redirect_target(Some(&session)), "/auth/login");
    assert_eq!(local_logout_redirect_target(None), "/auth/login");
}

#[test]
fn validate_upstream_discovery_rejects_issuer_mismatch() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let mut discovery = base_discovery(&issuer)?;
    discovery.issuer = require_some(normalize_issuer("https://other.example"), "normalize other")?;
    let profile = base_profile();
    let err = require_err(
        validate_upstream_discovery(&discovery, &issuer, &profile, "none", &[]),
        "issuer mismatch should be rejected",
    )?;
    assert!(err.contains("issuer mismatch"));
    Ok(())
}

#[test]
fn validate_upstream_discovery_rejects_endpoint_query_or_fragment() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let profile = base_profile();
    for (field, value) in [
        ("authorization_endpoint", "https://issuer.example/authorize?state=bad"),
        ("authorization_endpoint", "https://issuer.example/authorize#frag"),
        ("token_endpoint", "https://issuer.example/token?client_id=bad"),
        ("token_endpoint", "https://issuer.example/token#frag"),
        ("jwks_uri", "https://issuer.example/jwks?cache=1"),
        ("jwks_uri", "https://issuer.example/jwks#frag"),
        ("end_session_endpoint", "https://issuer.example/logout?state=bad"),
        ("end_session_endpoint", "https://issuer.example/logout#frag"),
    ] {
        let mut discovery = base_discovery(&issuer)?;
        match field {
            "authorization_endpoint" => discovery.authorization_endpoint = value.to_string(),
            "token_endpoint" => discovery.token_endpoint = value.to_string(),
            "jwks_uri" => discovery.jwks_uri = value.to_string(),
            "end_session_endpoint" => discovery.end_session_endpoint = Some(value.to_string()),
            _ => return Err(format!("unknown test field {field}")),
        }

        let err = require_err(
            validate_upstream_discovery(&discovery, &issuer, &profile, "none", &[]),
            "endpoint query or fragment should be rejected",
        )?;
        assert!(
            err.contains("query or fragment"),
            "{field} should fail with query/fragment error, got {err}"
        );
    }
    Ok(())
}

#[test]
fn validate_upstream_discovery_rejects_end_session_outside_allowlist() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let mut discovery = base_discovery(&issuer)?;
    discovery.end_session_endpoint = Some("https://logout.example/logout".to_string());
    let profile = base_profile();

    let err = require_err(
        validate_upstream_discovery(
            &discovery,
            &issuer,
            &profile,
            "none",
            &["issuer.example".to_string()],
        ),
        "end_session_endpoint outside allowlist should be rejected",
    )?;

    assert!(err.contains("allowlist"));
    Ok(())
}

#[test]
fn build_upstream_logout_session_rejects_unsafe_end_session_endpoint() -> TestResult {
    let issuer = "https://issuer.example";
    let id_token = logout_test_id_token(issuer);
    let policy = UpstreamLogoutPolicy {
        back_channel: false,
        session_hint_claim: Some("sid".to_string()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
    };
    let request = logout_test_request(issuer, policy.clone());

    for endpoint in [
        "https://issuer.example/logout?state=attacker",
        "https://issuer.example/logout#fragment",
        "https://127.0.0.1/logout",
    ] {
        let mut discovery = base_discovery(issuer)?;
        discovery.end_session_endpoint = Some(endpoint.to_string());

        let session = build_upstream_logout_session(
            Some(&policy),
            issuer,
            &discovery,
            &id_token,
            &request,
            &[],
        )
        .ok_or_else(|| "session".to_string())?;

        assert!(
            session.end_session_endpoint.is_none(),
            "{endpoint} should not be retained"
        );
    }
    Ok(())
}

#[test]
fn build_upstream_logout_session_rejects_endpoint_outside_allowlist() -> TestResult {
    let issuer = "https://issuer.example";
    let mut discovery = base_discovery(issuer)?;
    discovery.end_session_endpoint = Some("https://logout.example/logout".to_string());
    let id_token = logout_test_id_token(issuer);
    let policy = UpstreamLogoutPolicy {
        back_channel: false,
        session_hint_claim: Some("sid".to_string()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
    };
    let request = logout_test_request(issuer, policy.clone());

    let session = build_upstream_logout_session(
        Some(&policy),
        issuer,
        &discovery,
        &id_token,
        &request,
        &["issuer.example".to_string()],
    )
    .ok_or_else(|| "session".to_string())?;

    assert!(session.end_session_endpoint.is_none());
    Ok(())
}

#[test]
fn validate_upstream_discovery_rejects_missing_iss_support() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let mut discovery = base_discovery(&issuer)?;
    discovery.authorization_response_iss_parameter_supported = Some(false);
    let profile = base_profile();
    let err = require_err(
        validate_upstream_discovery(&discovery, &issuer, &profile, "none", &[]),
        "iss support should be required",
    )?;
    assert!(err.contains("iss parameter"));
    Ok(())
}

#[test]
fn validate_upstream_discovery_rejects_missing_pkce_s256() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let mut discovery = base_discovery(&issuer)?;
    discovery.code_challenge_methods_supported = Some(vec!["plain".to_string()]);
    let mut profile = base_profile();
    profile.require_iss_parameter = false;
    let err = require_err(
        validate_upstream_discovery(&discovery, &issuer, &profile, "none", &[]),
        "pkce s256 should be required",
    )?;
    assert!(err.contains("PKCE S256"));
    Ok(())
}

#[test]
fn validate_upstream_discovery_rejects_unsupported_auth_method() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let discovery = base_discovery(&issuer)?;
    let profile = base_profile();
    // base_discovery only lists "none"; client_secret_basic should be rejected.
    let err = require_err(
        validate_upstream_discovery(&discovery, &issuer, &profile, "client_secret_basic", &[]),
        "unsupported auth method should be rejected",
    )?;
    assert!(err.contains("client_secret_basic"));
    Ok(())
}

#[test]
fn validate_upstream_discovery_accepts_client_secret_basic() -> TestResult {
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let mut discovery = base_discovery(&issuer)?;
    discovery.token_endpoint_auth_methods_supported = Some(vec![
        "none".to_string(),
        "client_secret_basic".to_string(),
        "client_secret_post".to_string(),
    ]);
    let profile = base_profile();
    assert!(
        validate_upstream_discovery(&discovery, &issuer, &profile, "client_secret_basic", &[])
            .is_ok()
    );
    Ok(())
}

#[test]
fn validate_upstream_discovery_absent_methods_defaults_to_basic() -> TestResult {
    // RFC 8414 §2: when token_endpoint_auth_methods_supported is absent,
    // the default is ["client_secret_basic"].
    let issuer = require_some(
        normalize_issuer("https://issuer.example"),
        "normalize issuer",
    )?;
    let mut discovery = base_discovery(&issuer)?;
    discovery.token_endpoint_auth_methods_supported = None;
    // Relax iss requirement so it doesn't interfere.
    discovery.authorization_response_iss_parameter_supported = Some(true);
    let profile = base_profile();
    assert!(
        validate_upstream_discovery(&discovery, &issuer, &profile, "client_secret_basic", &[])
            .is_ok()
    );
    let err = require_err(
        validate_upstream_discovery(&discovery, &issuer, &profile, "none", &[]),
        "none should be rejected when methods absent (default is basic)",
    )?;
    assert!(err.contains("none"));
    Ok(())
}

#[test]
fn validate_return_to_rejects_absolute_paths() -> TestResult {
    for value in [
        "http://example.com",
        "https://example.com",
        "//evil",
        "/\\evil.example",
        "/\nLocation: https://evil.example",
        "foo/bar",
    ] {
        let err = require_err(
            validate_return_to(Some(value.to_string())),
            "absolute or invalid return_to should be rejected",
        )?;
        assert!(err.contains("return_to"));
    }
    Ok(())
}

#[test]
fn local_password_session_acr_is_derived_from_configured_capability() -> TestResult {
    assert_eq!(
        local_password_session_acr(Some("urn:pwd"), Some("urn:pwd")).map_err(str::to_string)?,
        Some("urn:pwd".to_string())
    );
    assert!(
        local_password_session_acr(Some("urn:pwd"), Some("urn:mfa")).is_err(),
        "local password authentication must not satisfy a stronger requested ACR"
    );
    assert!(
        local_password_session_acr(None, Some("urn:pwd")).is_err(),
        "an unconfigured local ACR must not be inferred from request input"
    );
    assert_eq!(
        local_password_session_acr(None, None).map_err(str::to_string)?,
        None
    );
    Ok(())
}
