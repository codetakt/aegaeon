use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(id: &str, secret: &str, method: &str) -> UpstreamAuthRequest {
    let now = SystemTime::now();
    UpstreamAuthRequest {
        browser_binding_digest: None,
        state: "state".into(),
        nonce: "nonce".into(),
        code_verifier: Some("verifier".into()),
        acr: None,
        issuer: "https://upstream.example".into(),
        client_id: id.into(),
        client_secret: Some(secret.into()),
        client_auth_method: method.into(),
        context: crate::upstream::UpstreamConnectionContext::new(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
        ),
        token_endpoint: "https://upstream.example/token".into(),
        jwks_uri: "https://upstream.example/jwks".into(),
        redirect_uri: "https://as.example/callback".into(),
        return_to: None,
        max_age: None,
        require_iss_parameter: true,
        jit_provisioning_policy: None,
        attribute_mappings: Vec::new(),
        claim_release_policy: None,
        logout_policy: None,
        issued_at: now,
        expires_at: now + Duration::from_secs(60),
    }
}

#[test]
fn oauth_basic_callback_builder_encodes_actual_authorization_header() -> TestResult {
    for (id, secret, expected) in [
        (
            "client: +%&=é",
            "secret: +%&=雪%2B",
            "client%3A+%2B%25%26%3D%C3%A9:secret%3A+%2B%25%26%3D%E9%9B%AA%252B",
        ),
        (
            "generated_ID-1",
            "secret_ID-2",
            "generated_ID-1:secret_ID-2",
        ),
    ] {
        let request = build_callback_token_request(
            &Client::new(),
            &fixture(id, secret, "client_secret_basic"),
            "code",
        )
        .build()?;
        assert_eq!(request.url().as_str(), "https://upstream.example/token");
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(
            request
                .headers()
                .get_all(reqwest::header::AUTHORIZATION)
                .iter()
                .count(),
            1
        );
        let auth = request.headers()[reqwest::header::AUTHORIZATION].to_str()?;
        assert_eq!(
            STANDARD.decode(auth.strip_prefix("Basic ").ok_or("Basic missing")?)?,
            expected.as_bytes()
        );
        let form: HashMap<String, String> = url::form_urlencoded::parse(
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .ok_or("body missing")?,
        )
        .into_owned()
        .collect();
        assert!(!form.contains_key("client_id"));
        assert!(!form.contains_key("client_secret"));
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "code");
        assert_eq!(form["redirect_uri"], "https://as.example/callback");
        assert_eq!(form["code_verifier"], "verifier");
    }
    Ok(())
}

#[test]
fn oauth_basic_callback_builder_preserves_other_methods() -> TestResult {
    for method in ["client_secret_post", "none"] {
        let request = build_callback_token_request(
            &Client::new(),
            &fixture("client+id", "secret%2B", method),
            "code",
        )
        .build()?;
        assert!(!request
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION));
        let form: HashMap<String, String> = url::form_urlencoded::parse(
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .ok_or("body missing")?,
        )
        .into_owned()
        .collect();
        assert_eq!(form["client_id"], "client+id");
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            (method == "client_secret_post").then_some("secret%2B")
        );
    }
    Ok(())
}
