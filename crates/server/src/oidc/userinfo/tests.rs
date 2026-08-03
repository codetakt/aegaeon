use super::*;
use crate::authcode::{
    AuthorizationCodeIssueInput, AuthorizationRequest, TokenIssuer, TokenRequest, TokenResponse,
    TokenValidator,
};
use crate::kms::InMemoryKeyManager;
use crate::oidc::OidcConfig;
use crate::policy::SecurityPolicy;
use crate::upstream::UpstreamClaimReleasePolicy;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

type TestResult<T = ()> = std::result::Result<T, Box<dyn StdError>>;

const TEST_RSA_PRIVATE_KEY_PEM: &str =
    include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem");

fn require_err<T, E>(
    result: std::result::Result<T, E>,
    message: &str,
) -> std::result::Result<E, io::Error> {
    match result {
        Ok(_) => Err(io::Error::other(message)),
        Err(err) => Ok(err),
    }
}

fn success_access_token(response: TokenResponse) -> std::result::Result<String, io::Error> {
    match response {
        TokenResponse::Success { access_token, .. } => Ok(access_token),
        TokenResponse::Error { .. } => Err(io::Error::other("expected success token response")),
    }
}

#[test]
fn test_filter_claims_by_scope() {
    let user = Userinfo {
        sub: "user123".to_string(),
        name: Some("John Doe".to_string()),
        email: Some("john@example.com".to_string()),
        email_verified: Some(true),
        phone_number: Some("+1234567890".to_string()),
        address: Some(Address {
            formatted: Some("123 Main St".to_string()),
            street_address: None,
            locality: None,
            region: None,
            postal_code: None,
            country: None,
        }),
        ..Default::default()
    };

    // Test profile scope
    let filtered = filter_claims_by_scope(user.clone(), &["profile".to_string()]);
    assert_eq!(filtered.name, Some("John Doe".to_string()));
    assert_eq!(filtered.email, None);

    // Test email scope
    let filtered = filter_claims_by_scope(user.clone(), &["email".to_string()]);
    assert_eq!(filtered.email, Some("john@example.com".to_string()));
    assert_eq!(filtered.name, None);

    // Test multiple scopes
    let filtered =
        filter_claims_by_scope(user.clone(), &["profile".to_string(), "email".to_string()]);
    assert_eq!(filtered.name, Some("John Doe".to_string()));
    assert_eq!(filtered.email, Some("john@example.com".to_string()));
}

#[test]
fn test_filter_claims_requires_scope() {
    let base = Userinfo {
        sub: "user123".to_string(),
        email: Some("john@example.com".to_string()),
        email_verified: Some(true),
        address: Some(Address {
            formatted: Some("123 Main St".to_string()),
            street_address: None,
            locality: None,
            region: None,
            postal_code: None,
            country: None,
        }),
        ..Default::default()
    };

    let filtered = filter_claims_by_scope(base.clone(), &[]);
    assert!(filtered.email.is_none());
    assert!(filtered.address.is_none());

    let filtered_email = filter_claims_by_scope(base.clone(), &["email".to_string()]);
    assert!(filtered_email.email.is_some());
    assert!(filtered_email.address.is_none());

    let filtered_address = filter_claims_by_scope(base, &["address".to_string()]);
    assert!(filtered_address.address.is_some());
    assert!(filtered_address.email.is_none());
}

#[test]
fn test_filter_claims_requires_profile_scope_for_custom_claims() {
    let mut custom_claims = HashMap::new();
    custom_claims.insert("roles".to_string(), serde_json::json!(["admins"]));
    let user = Userinfo {
        sub: "user123".to_string(),
        custom_claims,
        ..Default::default()
    };

    let filtered_without_profile = filter_claims_by_scope(user.clone(), &["openid".to_string()]);
    assert!(filtered_without_profile.custom_claims.is_empty());

    let filtered_with_profile =
        filter_claims_by_scope(user, &["openid".to_string(), "profile".to_string()]);
    assert_eq!(
        filtered_with_profile.custom_claims.get("roles"),
        Some(&serde_json::json!(["admins"]))
    );
}

fn enabled_oidc_config() -> TestResult<OidcConfig> {
    let signing_key = crate::oidc::OidcSigningKey::from_rsa_pem(
        "test-oidc-signing-key".to_string(),
        TEST_RSA_PRIVATE_KEY_PEM,
    )?;
    Ok(OidcConfig {
        issuer: "https://auth.example.com".to_string(),
        id_token_ttl_secs: 3600,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: false,
        backchannel_logout_enabled: false,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: true,
        signing_key,
        request_object_encryption_key: None,
    })
}

fn issue_tokens(scopes: &str, with_oidc: bool) -> TestResult<(UserinfoEndpoint, String)> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let issuer = if with_oidc {
        TokenIssuer::new_process_local_for_tests(key_manager.clone())
            .with_oidc(Some(enabled_oidc_config()?))
    } else {
        TokenIssuer::new_process_local_for_tests(key_manager.clone())
    };

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some(scopes.to_string()),
        state: Some("state-123".to_string()),
        nonce: if with_oidc {
            Some("nonce-123".to_string())
        } else {
            None
        },
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    };

    let (code, _) = if with_oidc {
        issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some("auth-session-userinfo".to_string()),
            ..AuthorizationCodeIssueInput::new(auth_req, "user123".to_string(), true, 0)
        })?
    } else {
        issuer.issue_authorization_code(auth_req, "user123".to_string())?
    };

    let token_req = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code),
        redirect_uri: Some("https://example.com/callback".to_string()),
        client_id: "test_client".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: None,
        request_object_claims: None,
    };

    let access_token = success_access_token(issuer.exchange_code_for_tokens(token_req, None)?)?;

    let policy = SecurityPolicy::default().with_sender_binding_enforcement(false);
    let validator = TokenValidator::with_policy(issuer.token_store.clone(), key_manager, policy);
    let mut provider_data = InMemoryUserProvider::new();
    provider_data.add_user(Userinfo {
        sub: "user123".to_string(),
        name: Some("User".to_string()),
        ..Default::default()
    });
    let provider: Arc<dyn UserProvider> = Arc::new(provider_data);
    let header = format!("Bearer {access_token}");
    validator.validate_bearer_token_with_meta(&header)?;
    let endpoint = UserinfoEndpoint::with_user_provider_for_tests(validator, provider);

    Ok((endpoint, header))
}

#[tokio::test]
async fn test_fetch_userinfo_with_openid_scope() -> TestResult {
    let (endpoint, header) = issue_tokens("openid profile", true)?;
    let result = endpoint.fetch_userinfo(&header, None, None).await?;
    assert_eq!(result.sub, "user123");
    Ok(())
}

#[tokio::test]
async fn test_fetch_userinfo_requires_openid_scope() -> TestResult {
    let (endpoint, header) = issue_tokens("profile email", false)?;
    let err = require_err(
        endpoint.fetch_userinfo(&header, None, None).await,
        "userinfo without openid scope must fail",
    )?;
    assert!(matches!(err, Error::InsufficientScope));
    Ok(())
}

#[tokio::test]
async fn test_fetch_userinfo_applies_claim_release_policy_to_custom_claims() -> TestResult {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let token_store = crate::authcode::store::TokenStore::new_process_local_for_tests();
    let access_token = crate::authcode::types::AccessToken::new(
        "test_client".to_string(),
        "user123".to_string(),
        Some("openid profile".to_string()),
        3600,
    );
    let access_token_value = access_token.token.clone();
    let _ = token_store
        .try_replace_access_token_record(access_token)
        .map_err(io::Error::other)?;

    let mut meta = crate::authcode::types::BearerTokenMeta::new(
        crate::authcode::types::BearerTokenMetaInput {
            token_id: access_token_value.clone(),
            client_id: "test_client".to_string(),
            user_id: "user123".to_string(),
            granted_scopes: vec!["openid".to_string(), "profile".to_string()],
            audience: crate::resource_audience::userinfo("https://auth.example.com"),
            sender_binding: None,
            authorization_details: None,
            auth_time_epoch_secs: None,
            acr: None,
            issued_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            refresh_parent: None,
        },
    );
    meta.claim_release_policy = Some(UpstreamClaimReleasePolicy {
        managed_custom_claims: vec!["organization".to_string(), "roles".to_string()],
        id_token_custom_claims: vec!["organization".to_string()],
        userinfo_custom_claims: vec!["roles".to_string()],
    });
    token_store
        .try_replace_bearer_meta_record(meta)
        .map_err(io::Error::other)?;

    let policy = SecurityPolicy::default().with_sender_binding_enforcement(false);
    let validator = TokenValidator::with_policy(token_store, key_manager, policy);

    let mut provider_data = InMemoryUserProvider::new();
    let mut custom_claims = HashMap::new();
    custom_claims.insert("roles".to_string(), serde_json::json!(["admins"]));
    custom_claims.insert("organization".to_string(), serde_json::json!("Platform"));
    custom_claims.insert("department".to_string(), serde_json::json!("Identity"));
    provider_data.add_user(Userinfo {
        sub: "user123".to_string(),
        name: Some("User".to_string()),
        custom_claims,
        ..Default::default()
    });
    let provider: Arc<dyn UserProvider> = Arc::new(provider_data);
    let endpoint = UserinfoEndpoint::with_user_provider_for_tests(validator, provider);

    let result = endpoint
        .fetch_userinfo(&format!("Bearer {access_token_value}"), None, None)
        .await?;

    assert_eq!(
        result.custom_claims.get("roles"),
        Some(&serde_json::json!(["admins"]))
    );
    assert_eq!(
        result.custom_claims.get("department"),
        Some(&serde_json::json!("Identity"))
    );
    assert!(!result.custom_claims.contains_key("organization"));
    Ok(())
}
