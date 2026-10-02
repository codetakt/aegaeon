//! Real routed introspection; public access keys and exact stored negative controls.
use super::*;
use crate::authcode::{AuthCodeStore, TokenIssuer, TokenValidator};
use crate::kms::{
    AccessTokenVerifier, InMemoryPublicJwtKeyManager, KeyManager, KeyManagerError,
    ManagedAccessTokenVerifier,
};
use crate::runtime_keys::{
    RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeySet, RuntimeKeyStatus,
    RuntimeKeyUsage,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn runtime_key(
    key: &dyn KeyManager,
    status: RuntimeKeyStatus,
    usage: RuntimeKeyUsage,
) -> TestResult<RuntimeKey> {
    Ok(RuntimeKey {
        environment_id: uuid::Uuid::new_v4(),
        usage,
        algorithm: RuntimeKeyAlgorithm::EdDsa,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status,
        retiring_expires_at_epoch_secs: (status == RuntimeKeyStatus::Retiring)
            .then_some(4_102_444_800),
        kid: key.key_id(),
        public_jwk: serde_json::from_value(key.jwt_signing_public_jwk().ok_or("public JWK")?)?,
        key_handle: format!(
            "{}{}",
            crate::key_encryption::KEY_HANDLE_ENVELOPE_PREFIX,
            URL_SAFE_NO_PAD.encode([0u8; 28])
        ),
        provider_configuration: json!({}),
    })
}

fn install(state: &mut AppState, keys: Vec<RuntimeKey>, strict: bool) -> TestResult {
    let verifier =
        ManagedAccessTokenVerifier::try_from_runtime_keys(&RuntimeKeySet::try_new(keys)?)?;
    state.tokens.validator = Arc::new(
        TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            state.keys.access_token.clone(),
            state.cfg.security_policy,
        )
        .with_access_token_verifier(Arc::new(verifier))
        .with_jwt_access_tokens_enabled(strict)
        .with_jwt_leeway_secs(0)
        .with_issuer(Some(state.issuer.to_string())),
    );
    Ok(())
}

async fn inner(state: &AppState, token: &str, active: bool) -> TestResult {
    assert!(
        state.tokens.store.try_verify_access_token(token)?.is_some(),
        "exact token lookup must succeed independently of JWT verification"
    );
    if token.contains('.') {
        let header = format!("Bearer {token}");
        for result in [
            state
                .tokens
                .validator
                .validate_bearer_token_with_meta(&header),
            state
                .tokens
                .validator
                .validate_bearer_token_with_meta_async(header.clone())
                .await,
        ] {
            assert_eq!(result.is_ok(), active, "{result:?}");
            if let Err(error) = result {
                assert!(!error.is_internal(), "{error}");
            }
        }
        assert_eq!(
            state.tokens.validator.introspect_token(token)["active"],
            active
        );
    }
    for jwt in [false, true] {
        let (status, body) = introspection(state, token, &reader(state, jwt), jwt).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["active"], active, "{body}");
        if !active {
            assert_eq!(body, json!({"active":false}));
        }
    }
    Ok(())
}

async fn issued(fixture: &Fixture, key: Arc<dyn KeyManager>, jwt: bool) -> TestResult<String> {
    let codes = AuthCodeStore::try_from_shared_store_env_with_ttl(
        Duration::from_secs(300),
        &fixture.namespace,
    )?;
    let issuer = TokenIssuer::with_stores(
        key,
        codes.clone(),
        fixture.state.tokens.store.as_ref().clone(),
    )
    .with_issuer(fixture.state.issuer.to_string())
    .with_jwt_access_tokens_enabled(jwt);
    Ok(super::grant_family::issue(fixture, &issuer, &codes)
        .await?
        .0)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn stored_jwt_issuance_switch_and_public_key_lifecycle_are_enforced_by_router() -> TestResult
{
    let mut fixture = Fixture::new(true).await?;
    let result = async {
        let key = Arc::new(InMemoryPublicJwtKeyManager::new()?);
        let token = issued(&fixture, key.clone(), true).await?;
        let opaque = issued(&fixture, key.clone(), false).await?;
        assert!(token.contains('.'));
        assert!(!opaque.contains('.'));
        // Issuance is disabled in the real fixture policy; verifier is purpose-bound.
        assert!(!fixture.state.cfg.enable_jwt_access_tokens);
        let active = runtime_key(
            key.as_ref(),
            RuntimeKeyStatus::Active,
            RuntimeKeyUsage::JwtAccessTokenSigning,
        )?;
        install(&mut fixture.state, vec![active.clone()], false)?;
        inner(&fixture.state, &token, true).await?;
        assert_eq!(
            fixture.state.tokens.validator.introspect_token(&token)["active"],
            true
        );
        for status in [
            RuntimeKeyStatus::Retiring,
            RuntimeKeyStatus::Revoked,
            RuntimeKeyStatus::Next,
        ] {
            install(
                &mut fixture.state,
                vec![runtime_key(
                    key.as_ref(),
                    status,
                    RuntimeKeyUsage::JwtAccessTokenSigning,
                )?],
                false,
            )?;
            inner(&fixture.state, &token, status == RuntimeKeyStatus::Retiring).await?;
        }
        let mut expired = runtime_key(
            key.as_ref(),
            RuntimeKeyStatus::Retiring,
            RuntimeKeyUsage::JwtAccessTokenSigning,
        )?;
        expired.retiring_expires_at_epoch_secs = Some(0);
        for keys in [
            vec![],
            vec![expired],
            vec![runtime_key(
                key.as_ref(),
                RuntimeKeyStatus::Active,
                RuntimeKeyUsage::JwtIntrospectionSigning,
            )?],
        ] {
            install(&mut fixture.state, keys, false)?;
            inner(&fixture.state, &token, false).await?;
        }
        install(&mut fixture.state, vec![active], true)?;
        inner(&fixture.state, &opaque, true).await?;
        assert!(fixture
            .state
            .tokens
            .validator
            .validate_bearer_token_with_meta(&format!("Bearer {opaque}"))
            .is_err());
        inner(&fixture.state, &token, true).await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

struct FaultVerifier(Arc<AtomicUsize>);
impl AccessTokenVerifier for FaultVerifier {
    fn verify_access_token_signature(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: &[u8],
    ) -> Result<bool, KeyManagerError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(KeyManagerError::OperationFailed)
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn stored_jwt_operational_failure_is_hidden_from_invisible_caller_and_recovers() -> TestResult
{
    let mut fixture = Fixture::new(true).await?;
    let result = async {
        let key = Arc::new(InMemoryPublicJwtKeyManager::new()?);
        let token = issued(&fixture, key.clone(), true).await?;
        let opaque = issued(&fixture, key.clone(), false).await?;
        let calls = Arc::new(AtomicUsize::new(0));
        fixture.state.tokens.validator = Arc::new(
            fixture
                .state
                .tokens
                .validator
                .as_ref()
                .clone()
                .with_access_token_verifier(Arc::new(FaultVerifier(calls.clone()))),
        );
        for jwt in [false, true] {
            for (caller, value) in [(OTHER, token.as_str()), (OWNER, "unknown.dotted.token")] {
                let (status, body) = introspection(&fixture.state, value, caller, jwt).await?;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body, json!({"active":false}));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
        }
        for jwt in [false, true] {
            let (status, body) =
                introspection(&fixture.state, &token, "unknown-caller", jwt).await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["error"], "invalid_client");
        }
        for value in [&token, &opaque] {
            let (status, body) = introspection(&fixture.state, value, OWNER, true).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, json!({"active":false}));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "owner denial precedes crypto"
            );
        }
        inner(&fixture.state, &opaque, true).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for jwt in [false, true] {
            let before = super::failures::metrics()?;
            let (status, body) =
                introspection(&fixture.state, &token, &reader(&fixture.state, jwt), jwt).await?;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["error"], "temporarily_unavailable");
            assert!(body.get("active").is_none());
            assert_eq!(super::failures::metrics()?, before);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        install(
            &mut fixture.state,
            vec![runtime_key(
                key.as_ref(),
                RuntimeKeyStatus::Active,
                RuntimeKeyUsage::JwtAccessTokenSigning,
            )?],
            false,
        )?;
        inner(&fixture.state, &token, true).await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

fn signed(key: &dyn KeyManager, header: &Value, payload: &Value) -> TestResult<String> {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?)
    );
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes())?)
    ))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn stored_jwt_schema_signature_and_audience_checks_preserve_sender_disclosure() -> TestResult
{
    let mut fixture = Fixture::new(true).await?;
    let result = async {
        let key = InMemoryPublicJwtKeyManager::new()?;
        install(&mut fixture.state, vec![runtime_key(&key, RuntimeKeyStatus::Active, RuntimeKeyUsage::JwtAccessTokenSigning)?], false)?;
        let now = crate::util::now_unix_epoch_secs()?;
        let base_header = json!({"kid":key.key_id(),"alg":"EdDSA","typ":"at+jwt"});
        for binding in [None, Some(SenderBinding::DPoP { jkt:"fixture-thumbprint".into() }), Some(SenderBinding::Mtls { fingerprint:"ab".repeat(32) })] {
            for variant in ["valid", "signature", "typ", "issuer", "expiry", "audience", "malformed"] {
                let (mut access, refresh, mut meta) = grant(&fixture.state, false, binding.clone());
                let mut header = base_header.clone();
                let mut payload = json!({"iss":fixture.state.issuer.as_str(),"sub":"subject","aud":meta.audience,"iat":now-120,"exp":now+300,"jti":uuid::Uuid::new_v4().to_string()});
                match variant {
                    "typ" => header["typ"] = json!("JWT"),
                    "issuer" => payload["iss"] = json!("https://wrong.example"),
                    "expiry" => payload["exp"] = json!(now-60),
                    "audience" => payload["aud"] = json!("https://other.example"),
                    _ => {}
                }
                access.token = signed(&key, &header, &payload)?;
                if variant == "signature" { access.token = format!("{}.{}", access.token.rsplit_once('.').ok_or("signature")?.0, URL_SAFE_NO_PAD.encode([0u8;64])); }
                if variant == "malformed" { access.token = format!("{}.broken", uuid::Uuid::new_v4()); }
                meta.token_id.clone_from(&access.token);
                fixture.state.tokens.store.store_issued_grant(access.clone(), refresh, meta)?;
                inner(&fixture.state, &access.token, variant == "valid").await?;
                if variant == "valid" {
                    let (_, body) = introspection(&fixture.state, &access.token, &reader(&fixture.state, true), true).await?;
                    match &access.cnf {
                        Some(CnfClaim::Jkt(value)) => assert_eq!(body["cnf"], json!({"jkt":value})),
                        Some(CnfClaim::X5tS256(value)) => assert_eq!(body["cnf"], json!({"x5t#S256":value})),
                        None => assert!(body.get("cnf").is_none()),
                    }
                }
            }
        }
        Ok(())
    }.await;
    fixture.finish(result).await
}
