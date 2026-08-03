use super::*;
use crate::authcode::types::{AuthorizationRequest, BearerTokenMeta, TokenRequest};
use crate::config::ConfigError;
use crate::end_user_profiles::OidcProfileClaims;
use crate::kms::{InMemoryKeyManager, KeyManager};
use crate::policy::SecurityPolicy;
use crate::upstream::UpstreamClaimReleasePolicy;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::sync::Arc;

const TEST_RSA_PRIVATE_KEY_PEM: &str =
    include_str!("../../../../tests/fixtures/rsa2048-private.pk8.pem");
type TestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(error) => fail_test!("{}: {:?}", $context, error),
        }
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}: unexpectedly succeeded", $context),
            Err(error) => error,
        }
    };
}

macro_rules! must_some {
    ($value:expr, $context:expr $(,)?) => {
        match $value {
            Some(value) => value,
            None => fail_test!("{}", $context),
        }
    };
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var_os(key);
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

struct PublicJwtTestKeyManager {
    signing_key: crate::oidc::OidcSigningKey,
}

impl PublicJwtTestKeyManager {
    fn new(kid: &str) -> Result<Self, String> {
        Ok(Self {
            signing_key: must_ok!(
                crate::oidc::OidcSigningKey::from_rsa_pem(
                    kid.to_string(),
                    TEST_RSA_PRIVATE_KEY_PEM,
                ),
                "test jwt signing key",
            ),
        })
    }
}

impl KeyManager for PublicJwtTestKeyManager {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, crate::kms::KeyManagerError> {
        let encoding_key = self
            .signing_key
            .local_encoding_key()
            .ok_or(crate::kms::KeyManagerError::KeyNotFound)?;
        let signature =
            jsonwebtoken::crypto::sign(msg, encoding_key, jsonwebtoken::Algorithm::RS256)
                .map_err(|_| crate::kms::KeyManagerError::OperationFailed)?;
        URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| crate::kms::KeyManagerError::OperationFailed)
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, crate::kms::KeyManagerError> {
        let expected = self.sign(msg)?;
        Ok(crate::util::constant_time_eq(&expected, sig))
    }

    fn key_id(&self) -> String {
        self.signing_key.kid().to_string()
    }

    fn jwt_signing_alg(&self) -> &'static str {
        "RS256"
    }

    fn jwt_signing_public_jwk(&self) -> Option<Value> {
        self.signing_key
            .jwks()
            .keys
            .first()
            .and_then(|jwk| serde_json::to_value(jwk).ok())
    }

    fn rotate(&self) -> Result<(), crate::kms::KeyManagerError> {
        Err(crate::kms::KeyManagerError::OperationFailed)
    }

    fn revoke(&self) -> Result<(), crate::kms::KeyManagerError> {
        Err(crate::kms::KeyManagerError::OperationFailed)
    }
}

fn public_jwt_key_manager() -> Result<Arc<dyn KeyManager>, String> {
    PublicJwtTestKeyManager::new("test-jwt-signing-key")
        .map(|manager| Arc::new(manager) as Arc<dyn KeyManager>)
}

struct JwtAccessTokenRawJsonEnvGuard {
    _header_backend: EnvVarGuard,
    _payload_backend: EnvVarGuard,
    _lock: std::sync::MutexGuard<'static, ()>,
}

fn jwt_access_token_raw_json_env_guard() -> Result<JwtAccessTokenRawJsonEnvGuard, String> {
    let lock = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let header_key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        aegaeon_jose::raw_json::RawJsonSurface::JwtAccessTokenHeader,
    );
    let payload_key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        aegaeon_jose::raw_json::RawJsonSurface::JwtAccessTokenPayload,
    );
    Ok(JwtAccessTokenRawJsonEnvGuard {
        _header_backend: EnvVarGuard::new(header_key, Some("verified-structural-v1")),
        _payload_backend: EnvVarGuard::new(payload_key, Some("verified-structural-v1")),
        _lock: lock,
    })
}

fn raw_json_structural_parser_unavailable(payload: &[u8]) -> bool {
    matches!(
        ffi::raw_json_structural::parse_raw_json_structural(payload),
        Err(ffi::raw_json_structural::RawJsonStructuralParseError::ParserUnavailable)
    )
}

fn store_access_token(token_store: &TokenStore, token: AccessToken) -> Result<String, String> {
    Ok(must_ok!(
        token_store.try_replace_access_token_record(token),
        "store access token",
    ))
}

fn store_jwt_access_token(token_store: &TokenStore, token: &str) -> TestResult {
    let _ = store_access_token(
        token_store,
        AccessToken {
            token: token.to_string(),
            token_type: "Bearer".to_string(),
            client_id: "client".to_string(),
            user_id: "client".to_string(),
            scope: None,
            expires_in: 3600,
            created_at: SystemTime::now(),
            cnf: None,
        },
    )?;
    Ok(())
}

fn verify_access_token(
    token_store: &TokenStore,
    token: &str,
) -> Result<Option<AccessToken>, String> {
    Ok(must_ok!(
        token_store.try_verify_access_token(token),
        "verify access token",
    ))
}

fn get_bearer_meta(
    token_store: &TokenStore,
    token: &str,
) -> Result<Option<BearerTokenMeta>, String> {
    Ok(must_ok!(
        token_store.try_get_bearer_meta(token),
        "get bearer metadata",
    ))
}

fn is_refresh_revoked(token_store: &TokenStore, token: &str) -> Result<bool, String> {
    Ok(must_ok!(
        token_store.try_is_refresh_revoked(token),
        "check refresh revocation",
    ))
}

#[test]
fn access_token_introspection_exp_rejects_unrepresentable_expiry() {
    let access_token = AccessToken {
        token: "access".to_string(),
        token_type: "Bearer".to_string(),
        client_id: "client".to_string(),
        user_id: "user".to_string(),
        scope: None,
        expires_in: u64::MAX,
        created_at: std::time::UNIX_EPOCH + Duration::from_secs(1),
        cnf: None,
    };

    assert_eq!(access_token_introspection_exp(&access_token), None);
}

fn enabled_oidc_config() -> Result<OidcConfig, String> {
    let signing_key = must_ok!(
        crate::oidc::OidcSigningKey::from_rsa_pem(
            "test-oidc-signing-key".to_string(),
            TEST_RSA_PRIVATE_KEY_PEM,
        ),
        "oidc signing key",
    );
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

fn decode_jwt_part(part: &str) -> Result<Value, String> {
    let bytes = must_ok!(URL_SAFE_NO_PAD.decode(part), "base64url decode");
    Ok(must_ok!(serde_json::from_slice(&bytes), "json decode"))
}

fn sign_raw_jwt_parts(
    header_json: &str,
    payload_json: &str,
    key_manager: &dyn KeyManager,
) -> Result<String, String> {
    let now = unix_epoch_now_secs();
    let payload_json = payload_json
        .replace(
            "unix_epoch_now_secs().saturating_add(300)",
            &now.saturating_add(300).to_string(),
        )
        .replace("unix_epoch_now_secs()", &now.to_string());
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = must_ok!(key_manager.sign(signing_input.as_bytes()), "sign raw token");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}

fn authorization_request(scope: &str, resource: Option<&str>) -> AuthorizationRequest {
    AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: resource.map(ToString::to_string),
        authorization_details: None,
        scope: Some(scope.to_string()),
        state: Some("state-123".to_string()),
        nonce: Some("nonce-123".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    }
}

fn token_request_for_code(code: String, resource: Option<&str>) -> TokenRequest {
    TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code),
        redirect_uri: Some("https://example.com/callback".to_string()),
        client_id: "test_client".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: resource.map(ToString::to_string),
        request_object_claims: None,
    }
}
