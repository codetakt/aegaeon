//! Malformed server values must not reach failure reports or their error chains.
use super::super::wire::{
    response_json, IntrospectionResponse, OAuthError, ParSuccess, TokenResponse, Userinfo,
};
use super::protocol_fixture::{
    assert_http, assert_report_redaction, header, OidcIssuer, SENSITIVE_MARKER,
};
use super::{
    fixture_profile, fixture_reply, fixture_token, http_fixture, tls_fixture, ScenarioExecutor,
};
use serde::de::DeserializeOwned;

fn malformed_introspection() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"active":SENSITIVE_MARKER})).unwrap()
}

fn malformed_jwks() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"keys":[{
        "kty":"RSA", "kid":"signing", "n":"AQAB", "e":"AQAB", "alg":SENSITIVE_MARKER
    }]}))
    .unwrap()
}

#[tokio::test]
async fn revocation_malformed_confirmation_redacts_report_and_invalidates_issued_token() {
    let body = malformed_introspection();
    assert!(serde_json::from_slice::<IntrospectionResponse>(&body)
        .unwrap_err()
        .to_string()
        .contains(SENSITIVE_MARKER));
    let (base, thread, client) = tls_fixture(4, move |step, request, base| match step {
        0 => super::authorization_fixture_reply(request, base).0,
        1 => {
            assert!(request.starts_with("POST /token "));
            fixture_reply(200, serde_json::to_vec(&fixture_token(false, 300)).unwrap())
        }
        2 => {
            assert!(request.starts_with("POST /revoke "));
            assert!(header(request, "Authorization")
                .unwrap()
                .starts_with("Basic "));
            assert!(request.ends_with("token=token&token_type_hint=access_token"));
            fixture_reply(200, Vec::new())
        }
        3 => {
            assert!(request.starts_with("POST /introspect "));
            assert!(header(request, "Authorization")
                .unwrap()
                .starts_with("Basic "));
            assert!(request.ends_with("token=token"));
            fixture_reply(200, body.clone())
        }
        _ => panic!("unexpected fixture request"),
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, false))).unwrap();
    executor.client = client;
    executor.ensure_token(false).await.unwrap();
    assert!(executor.cached_access_token.is_some());
    let error = executor.revocation_flow().await.unwrap_err();
    assert_eq!(error.to_string(), "invalid introspection response");
    assert_eq!(error.chain().count(), 1);
    assert!(executor.cached_access_token.is_none());
    thread.join().unwrap();
    let accounting = executor.take_accounting();
    assert_http(
        &accounting,
        &[
            ("GET /authorize", 1),
            ("POST /token", 1),
            ("POST /revoke", 1),
            ("POST /introspect", 1),
        ],
        &[
            ("GET /authorize 302", 1),
            ("POST /token 200", 1),
            ("POST /revoke 200", 1),
            ("POST /introspect 200", 1),
        ],
    );
    assert!(accounting.nonce_challenges.is_empty());
    assert!(accounting.nonce_retries.is_empty());
    assert_report_redaction(&error, "revocation", accounting).await;
}

#[tokio::test]
async fn introspection_missing_auth_malformed_oauth_response_has_fixed_report_error() {
    let (base, thread, client) = tls_fixture(1, move |_, request, _| {
        assert!(request.starts_with("POST /introspect "));
        assert!(header(request, "Authorization").is_none());
        assert!(header(request, "Cookie").is_none());
        let mut reply = fixture_reply(
            401,
            serde_json::to_vec(&serde_json::json!({
                "error": 7, "description": SENSITIVE_MARKER
            }))
            .unwrap(),
        );
        reply.headers.push((
            "WWW-Authenticate".into(),
            "Basic error=\"invalid_client\"".into(),
        ));
        reply
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, false))).unwrap();
    executor.client = client;
    let error = executor
        .introspection_requires_auth_flow()
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "invalid OAuth error response");
    assert_eq!(error.chain().count(), 1);
    thread.join().unwrap();
    let accounting = executor.take_accounting();
    assert_http(
        &accounting,
        &[("POST /introspect", 1)],
        &[("POST /introspect 401", 1)],
    );
    assert_report_redaction(&error, "introspection-missing-client-auth", accounting).await;
}

#[tokio::test]
async fn standalone_jwks_malformed_key_redacts_serde_value_and_keeps_response_accounting() {
    let body = malformed_jwks();
    let digest = super::sha256(&body);
    assert!(serde_json::from_slice::<jsonwebtoken::jwk::JwkSet>(&body)
        .unwrap_err()
        .to_string()
        .contains(SENSITIVE_MARKER));
    let (base, thread) = http_fixture(1, move |_, request, _| {
        assert!(request.starts_with("GET /.well-known/jwks.json "));
        assert!(header(request, "Authorization").is_none());
        fixture_reply(200, body.clone())
    });
    let mut executor = ScenarioExecutor::with_profile(base, None).unwrap();
    let error = executor.jwks_flow().await.unwrap_err();
    assert_eq!(error.to_string(), "invalid JWKS response");
    assert_eq!(error.chain().count(), 1);
    assert_eq!(executor.jwks_sha256.as_deref(), Some(digest.as_str()));
    thread.join().unwrap();
    let accounting = executor.take_accounting();
    assert_http(
        &accounting,
        &[("GET /.well-known/jwks.json", 1)],
        &[("GET /.well-known/jwks.json 200", 1)],
    );
    assert_report_redaction(&error, "jwks", accounting).await;
}

#[tokio::test]
async fn oidc_malformed_issuer_key_never_exposes_verification_error_chain_or_calls_userinfo() {
    let mut issuer = OidcIssuer::new();
    issuer.jwks = malformed_jwks();
    let digest = super::sha256(&issuer.jwks);
    let (base, thread, client) = tls_fixture(3, move |step, request, base| {
        issuer.setup_reply(step, request, base).unwrap()
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true))).unwrap();
    executor.client = client;
    let error = executor.userinfo_flow().await.unwrap_err();
    assert_eq!(error.to_string(), "invalid ID Token or issuer JWKS");
    assert_eq!(error.chain().count(), 1);
    assert!(executor.cached_userinfo_access_token.is_none());
    assert_eq!(executor.jwks_sha256.as_deref(), Some(digest.as_str()));
    thread.join().unwrap();
    let accounting = executor.take_accounting();
    assert_http(
        &accounting,
        &[
            ("GET /authorize", 1),
            ("POST /token", 1),
            ("GET /.well-known/jwks.json", 1),
        ],
        &[
            ("GET /authorize 302", 1),
            ("POST /token 200", 1),
            ("GET /.well-known/jwks.json 200", 1),
        ],
    );
    assert_report_redaction(&error, "userinfo", accounting).await;
}

fn assert_typed_json_redaction<T: DeserializeOwned>(
    value: &serde_json::Value,
    message: &'static str,
) {
    let body = serde_json::to_vec(value).unwrap();
    assert!(String::from_utf8_lossy(&body).contains(SENSITIVE_MARKER));
    let error = response_json::<T>(&body, message).err().unwrap();
    assert_eq!(error.to_string(), message);
    assert_eq!(error.chain().count(), 1);
    assert!(!format!("{error:#}").contains(SENSITIVE_MARKER));
    assert!(!format!("{error:?}").contains(SENSITIVE_MARKER));
}

#[test]
fn response_json_consumers_drop_untrusted_values_and_serde_sources() {
    let mut token = fixture_token(false, 300);
    token["expires_in"] = SENSITIVE_MARKER.into();
    assert_typed_json_redaction::<TokenResponse>(&token, "invalid token response");
    assert_typed_json_redaction::<IntrospectionResponse>(
        &serde_json::json!({"active":SENSITIVE_MARKER}),
        "invalid introspection response",
    );
    assert_typed_json_redaction::<ParSuccess>(
        &serde_json::json!({"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":SENSITIVE_MARKER}),
        "invalid PAR response",
    );
    assert_typed_json_redaction::<OAuthError>(
        &serde_json::json!({"error":[SENSITIVE_MARKER]}),
        "invalid OAuth error response",
    );
    assert_typed_json_redaction::<Userinfo>(
        &serde_json::json!({"sub":[SENSITIVE_MARKER]}),
        "invalid UserInfo response",
    );
    assert_typed_json_redaction::<jsonwebtoken::jwk::JwkSet>(
        &serde_json::from_slice(&malformed_jwks()).unwrap(),
        "invalid JWKS response",
    );
    let malformed = format!("{{\"issuer\":\"{SENSITIVE_MARKER}\",\"token_endpoint\":");
    let error =
        response_json::<serde_json::Value>(malformed.as_bytes(), "invalid discovery response")
            .unwrap_err();
    assert_eq!(error.to_string(), "invalid discovery response");
    assert_eq!(error.chain().count(), 1);
    assert!(!format!("{error:#}").contains(SENSITIVE_MARKER));
}
