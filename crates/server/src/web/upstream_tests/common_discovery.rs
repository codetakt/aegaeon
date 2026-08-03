use super::*;
use axum::http::{header, HeaderValue, StatusCode};

type TestResult = Result<(), String>;
const TEST_ISSUER: &str = "https://issuer.example";

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var(key).ok();
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.as_deref() {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn headers_with_csrf_cookie(cookie_name: &str, token: &str) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();
    let cookie = format!("{cookie_name}={token}");
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&cookie).map_err(|err| err.to_string())?,
    );
    Ok(headers)
}

#[test]
fn csrf_cookie_matches_rejects_duplicate_cookie_headers() -> TestResult {
    let token = "csrf-token";
    let mut headers = HeaderMap::new();
    headers.append(
        header::COOKIE,
        HeaderValue::from_str(&format!("{LOCAL_AUTH_CSRF_COOKIE_NAME}={token}"))
            .map_err(|err| err.to_string())?,
    );
    headers.append(
        header::COOKIE,
        HeaderValue::from_str(&format!("{LOCAL_AUTH_CSRF_COOKIE_NAME}={token}"))
            .map_err(|err| err.to_string())?,
    );

    assert!(!csrf_cookie_matches(
        &headers,
        LOCAL_AUTH_CSRF_COOKIE_NAME,
        token
    ));
    Ok(())
}

fn require_some<T>(value: Option<T>, context: &str) -> Result<T, String> {
    value.ok_or_else(|| context.to_string())
}

fn require_err<T, E>(result: Result<T, E>, context: &str) -> Result<E, String> {
    match result {
        Err(err) => Ok(err),
        Ok(_) => Err(context.to_string()),
    }
}

fn form_pairs(fields: &[(&str, &str)]) -> axum::extract::Form<Vec<(String, String)>> {
    axum::extract::Form(
        fields
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect(),
    )
}

fn form_pairs_with_duplicate(
    fields: &[(&str, &str)],
    field: &str,
    duplicate_value: &str,
) -> axum::extract::Form<Vec<(String, String)>> {
    let mut params = form_pairs(fields).0;
    params.push((field.to_string(), duplicate_value.to_string()));
    axum::extract::Form(params)
}

fn test_upstream_connection(
    environment_id: uuid::Uuid,
    connection_id: uuid::Uuid,
    client_auth_method: &str,
    client_secret_encrypted: Option<Vec<u8>>,
) -> UpstreamConnection {
    UpstreamConnection {
        id: connection_id,
        connection_identifier: "test-connection".to_string(),
        team_id: uuid::Uuid::new_v4(),
        tenant_id: uuid::Uuid::new_v4(),
        environment_id,
        configuration_version_id: uuid::Uuid::new_v4(),
        connection_type: "OIDC".to_string(),
        issuer_url: "https://issuer.example".to_string(),
        client_id: "client".to_string(),
        client_auth_method: client_auth_method.to_string(),
        client_secret_encrypted,
        jit_provisioning_policy: None,
        attribute_mappings: Vec::new(),
        claim_release_policy: None,
        logout_policy: None,
    }
}

fn base_profile() -> oauth_profile::ResolvedProfile {
    oauth_profile::ResolvedProfile {
        id: "profile-id".to_string(),
        name: "upstream".to_string(),
        require_pkce: true,
        require_state_parameter: true,
        require_iss_parameter: true,
        sender_constrained: SenderConstraint::None,
        enforce_refresh_sender_binding: false,
        allowed_grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_methods_allowed: vec!["none".to_string()],
    }
}

fn base_discovery(issuer: &str) -> Result<OidcDiscovery, String> {
    let base_url = issuer.trim_end_matches('/');
    let mut discovery = OidcDiscovery::new_with_runtime_config(
        issuer,
        base_url,
        &crate::metadata::MetadataRuntimeConfig::default(),
    );
    discovery.token_endpoint_auth_methods_supported = Some(vec!["none".to_string()]);
    discovery.authorization_response_iss_parameter_supported = Some(true);
    discovery.code_challenge_methods_supported = Some(vec!["S256".to_string()]);
    Ok(discovery)
}

fn logout_test_id_token(issuer: &str) -> IdToken {
    crate::oidc::IdTokenBuilder::try_new(
        issuer.to_string(),
        "subject-123".to_string(),
        "client".to_string(),
    )
    .expect("test issuer is valid")
    .session_id("sid-123".to_string())
    .claim("email".to_string(), json!("user@example.com"))
    .build()
}

fn logout_test_request(
    issuer: &str,
    policy: UpstreamLogoutPolicy,
) -> crate::upstream::UpstreamAuthRequest {
    let now = SystemTime::now();
    crate::upstream::UpstreamAuthRequest {
        state: "state".to_string(),
        nonce: "nonce".to_string(),
        code_verifier: None,
        acr: None,
        issuer: issuer.to_string(),
        client_id: "client".to_string(),
        client_secret: None,
        client_auth_method: "none".to_string(),
        context: crate::upstream::UpstreamConnectionContext::new(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        ),
        token_endpoint: "https://issuer.example/token".to_string(),
        jwks_uri: "https://issuer.example/jwks".to_string(),
        redirect_uri: "https://issuer.example/callback".to_string(),
        return_to: None,
        max_age: None,
        require_iss_parameter: false,
        jit_provisioning_policy: None,
        attribute_mappings: Vec::new(),
        claim_release_policy: None,
        logout_policy: Some(policy),
        issued_at: now,
        expires_at: now + Duration::from_secs(60),
    }
}

fn jwks_from_keys(keys: &[Value]) -> Result<JwkSet, String> {
    let value = json!({ "keys": keys });
    JwkSet::from_value(value).map_err(|err| err.to_string())
}

fn rsa_key(kid: &str) -> Value {
    rsa_key_with_material(kid, "00", "AQAB")
}

fn rsa_key_with_material(kid: &str, n: &str, e: &str) -> Value {
    json!({
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": n,
        "e": e
    })
}

fn federation_metadata_from_discovery(discovery: &OidcDiscovery) -> Value {
    json!({
        "issuer": discovery.issuer.as_str(),
        "authorization_endpoint": discovery.authorization_endpoint.as_str(),
        "token_endpoint": discovery.token_endpoint.as_str(),
        "jwks_uri": discovery.jwks_uri.as_str()
    })
}

#[test]
fn validate_upstream_discovery_matches_federation_metadata_rejects_endpoint_mismatch() -> TestResult
{
    let discovery = base_discovery(TEST_ISSUER)?;
    for (key, replacement) in [
        ("token_endpoint", "https://issuer.example/other-token"),
        ("jwks_uri", "https://issuer.example/other-jwks"),
    ] {
        let mut metadata = federation_metadata_from_discovery(&discovery);
        metadata[key] = json!(replacement);

        let err = require_err(
            validate_upstream_discovery_matches_federation_metadata(
                &discovery,
                TEST_ISSUER,
                &metadata,
            ),
            "discovery endpoint mismatch must fail closed",
        )?;

        assert!(
            err.contains(key),
            "expected {key} mismatch error, got {err}"
        );
    }
    Ok(())
}

#[test]
fn validate_upstream_jwks_matches_federation_metadata_rejects_kid_reuse_with_different_material(
) -> TestResult {
    let fetched = jwks_from_keys(&[rsa_key_with_material("k1", "00", "AQAB")])?;
    let metadata = json!({
        "jwks": {
            "keys": [rsa_key_with_material("k1", "01", "AQAB")]
        }
    });

    let err = require_err(
        validate_upstream_jwks_matches_federation_metadata(&fetched, &metadata),
        "same kid with different key material must fail closed",
    )?;

    assert!(err.contains("does not match"));
    Ok(())
}

#[test]
fn validate_upstream_jwks_matches_federation_metadata_accepts_same_material_without_alg(
) -> TestResult {
    let fetched = jwks_from_keys(&[rsa_key("k1")])?;
    let mut metadata_key = rsa_key("k1");
    metadata_key
        .as_object_mut()
        .ok_or_else(|| "test key must be an object".to_string())?
        .remove("alg");
    let metadata = json!({
        "jwks": {
            "keys": [metadata_key]
        }
    });

    validate_upstream_jwks_matches_federation_metadata(&fetched, &metadata)?;
    Ok(())
}

#[test]
fn parse_upstream_jwks_body_accepts_valid_jwks() -> TestResult {
    let body = br#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "upstream-rs256",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "00",
                    "e": "AQAB"
                }
            ]
        }"#;

    let jwks = parse_upstream_jwks_body(body)?;
    assert_eq!(jwks.keys().len(), 1);
    assert!(jwks.signature_keys().next().is_some());
    Ok(())
}

#[test]
fn parse_upstream_jwks_body_rejects_duplicate_nested_object_key() -> TestResult {
    let body = br#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "first",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "00",
                    "e": "AQAB",
                    "kid": "second"
                }
            ]
        }"#;

    let err = require_err(
        parse_upstream_jwks_body(body),
        "duplicate nested JWK members must fail before JWK parsing",
    )?;
    assert_eq!(err, "upstream jwks response contains duplicate object keys");
    Ok(())
}

#[test]
fn parse_upstream_discovery_body_rejects_duplicate_object_key() -> TestResult {
    let discovery = serde_json::to_string(&base_discovery("https://issuer.example")?)
        .map_err(|err| err.to_string())?;
    let duplicated = format!(
        r#"{{"issuer":"https://evil.example",{}"#,
        discovery
            .strip_prefix('{')
            .ok_or_else(|| "serialized discovery object".to_string())?
    );

    let err = require_err(
        parse_upstream_discovery_body(duplicated.as_bytes()),
        "duplicate discovery members must fail before typed decode",
    )?;
    assert_eq!(
        err,
        "upstream discovery response contains duplicate object keys"
    );
    Ok(())
}
