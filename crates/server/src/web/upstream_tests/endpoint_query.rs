use super::*;

#[test]
fn upstream_logout_query_preserves_vendor_bytes_and_reuses_equivalent_hint() -> TestResult {
    let policy = UpstreamLogoutPolicy {
        back_channel: false,
        session_hint_claim: Some("sid".into()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
    };
    let issuer = "https://issuer.example";
    let mut discovery = base_discovery(issuer)?;
    let request = logout_test_request(issuer, policy.clone());
    let token = logout_test_id_token(issuer);
    for query in [
        "vendor=%2f&vendor=two+words&blank=",
        "vendor=%2f&logout%5Fhint=sid-123",
        "",
    ] {
        discovery.end_session_endpoint = Some(format!("https://issuer.example/logout?{query}"));
        let session =
            build_upstream_logout_session(Some(&policy), issuer, &discovery, &token, &request, &[])
                .ok_or("session")?;
        let target = build_upstream_logout_redirect_target(&session, &[]).ok_or("target")?;
        let url = url::Url::parse(&target).map_err(|e| e.to_string())?;
        assert!(url.query().ok_or("query")?.starts_with(query));
        let hints = url
            .query_pairs()
            .filter(|(key, _)| key == "logout_hint")
            .map(|(_, v)| v.into_owned())
            .collect::<Vec<_>>();
        assert_eq!(hints, vec!["sid-123"]);
    }
    Ok(())
}

#[test]
fn upstream_logout_non_relay_rejects_reserved_query_with_or_without_hint() -> TestResult {
    let policy = UpstreamLogoutPolicy {
        back_channel: false,
        session_hint_claim: Some("sid".into()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
    };
    let issuer = "https://issuer.example";
    let mut discovery = base_discovery(issuer)?;
    discovery.end_session_endpoint = Some(format!("{issuer}/logout"));
    let mut session = build_upstream_logout_session(
        Some(&policy),
        issuer,
        &discovery,
        &logout_test_id_token(issuer),
        &logout_test_request(issuer, policy.clone()),
        &[],
    )
    .ok_or("session")?;
    for hint in [Some("sid-123".to_string()), None] {
        session.session_hint_value = hint;
        for query in [
            "state=attacker",
            "st%61te=attacker",
            "state=one&state=two",
            "state=",
            "post_logout_redirect_uri=https%3A%2F%2Fevil.example",
            "post_logout_redirect%5Furi=https%3A%2F%2Fevil.example",
            "post_logout_redirect_uri=",
            "bad%name=value",
        ] {
            session.end_session_endpoint = Some(format!("{issuer}/logout?{query}"));
            assert!(build_upstream_logout_redirect_target(&session, &[]).is_none());
        }
        session.end_session_endpoint = Some(format!("{issuer}/logout?vendor=%2f&blank="));
        assert!(build_upstream_logout_redirect_target(&session, &[]).is_some());
    }
    Ok(())
}
