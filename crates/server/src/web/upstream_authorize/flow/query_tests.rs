use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> (UpstreamAuthorizeInput, UpstreamAuthorizeFlowState) {
    (
        UpstreamAuthorizeInput {
            return_to: None,
            scopes: vec!["openid".into()],
            scope: "openid".into(),
            acr: Some("level 2".into()),
            max_age: Some(60),
        },
        UpstreamAuthorizeFlowState {
            redirect_uri: "https://as.example/callback".into(),
            state_token: "state".into(),
            nonce: "nonce".into(),
            code_challenge: Some("challenge".into()),
            browser_secret: "browser".into(),
            expires_at: SystemTime::now() + std::time::Duration::from_secs(60),
            ttl_secs: 60,
        },
    )
}

#[test]
fn upstream_authorize_query_preserves_vendor_bytes_and_single_equivalent_protocol_values(
) -> TestResult {
    let (input, flow) = fixture();
    for query in [
        "vendor=%2f%2F&vendor=two+words&blank=&st%61te=state&scope=openid&acr_values=level+2",
        "",
    ] {
        let mut discovery = crate::web::upstream_tests::base_discovery("https://issuer.example")?;
        discovery.authorization_endpoint = format!("https://issuer.example/authorize?{query}");
        let response = build_upstream_authorize_redirect_response(
            "https://as.example",
            &discovery,
            "client",
            &input,
            &flow,
            true,
        )
        .map_err(|e| format!("redirect {}", e.status()))?;
        let url = Url::parse(response.headers()[header::LOCATION].to_str()?)?;
        assert!(url.query().ok_or("query")?.starts_with(query));
        let pairs = url.query_pairs().collect::<Vec<_>>();
        for (name, expected) in [
            ("response_type", "code"),
            ("client_id", "client"),
            ("redirect_uri", flow.redirect_uri.as_str()),
            ("scope", "openid"),
            ("state", "state"),
            ("nonce", "nonce"),
            ("code_challenge", "challenge"),
            ("code_challenge_method", "S256"),
            ("acr_values", "level 2"),
            ("max_age", "60"),
            ("prompt", "login"),
        ] {
            let found = pairs
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.as_ref())
                .collect::<Vec<_>>();
            assert_eq!(found, vec![expected], "{name}");
        }
        assert!(response.headers().contains_key(header::SET_COOKIE));
    }
    Ok(())
}

#[test]
fn upstream_authorize_query_rejects_generated_collisions_and_request_objects_without_redirect_cookie(
) -> TestResult {
    let (input, flow) = fixture();
    for query in [
        "state=other",
        "nonce=other",
        "redirect_uri=https%3A%2F%2Fevil.example",
        "code_challenge=other",
        "code_challenge_method=plain",
        "scope=other",
        "client_id=other",
        "response_type=token",
        "acr_values=other",
        "max_age=30",
        "prompt=none",
        "state=state&st%61te=state",
        "state=%FF",
        "st%ZZate=state",
        "request=signed",
        "request%5Furi=https%3A%2F%2Fissuer.example%2Frequest",
    ] {
        let mut discovery = crate::web::upstream_tests::base_discovery("https://issuer.example")?;
        discovery.authorization_endpoint = format!("https://issuer.example/authorize?{query}");
        let response = build_upstream_authorize_redirect_response(
            "https://as.example",
            &discovery,
            "client",
            &input,
            &flow,
            true,
        )
        .expect_err("collision must fail");
        assert!(
            !response.headers().contains_key(header::SET_COOKIE),
            "{query}"
        );
        assert!(
            !response.headers().contains_key(header::LOCATION),
            "{query}"
        );
    }
    Ok(())
}
