use super::*;
use crate::kms::{AccessTokenVerifier, InMemoryPublicJwtKeyManager, KeyManagerError};
use std::sync::atomic::{AtomicUsize, Ordering};

struct FailingVerifier(Arc<AtomicUsize>);
impl AccessTokenVerifier for FailingVerifier {
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

fn signed(manager: &dyn KeyManager, payload: Value) -> Result<String, String> {
    sign_raw_jwt_parts(
        &json!({"kid":manager.key_id(),"alg":manager.jwt_signing_alg(),"typ":"at+jwt"}).to_string(),
        &payload.to_string(),
        manager,
    )
}

fn claims() -> Value {
    json!({"iss":"https://issuer.example","sub":"client","aud":"client","iat":unix_epoch_now_secs(),"exp":unix_epoch_now_secs()+300,"jti":"id"})
}

async fn check(validator: &TokenValidator, token: &str, valid: bool, internal: bool) {
    let header = format!("Bearer {token}");
    for result in [
        validator.validate_bearer_token_with_meta(&header),
        validator
            .validate_bearer_token_with_meta_async(header.clone())
            .await,
    ] {
        assert_eq!(result.is_ok(), valid, "{result:?}");
        if let Err(error) = result {
            assert_eq!(error.is_internal(), internal, "{error}");
        }
    }
    assert_eq!(validator.introspect_token(token)["active"], valid);
    if !valid {
        assert_eq!(validator.introspect_token(token), json!({"active":false}));
    }
}

#[tokio::test]
async fn stored_jwt_mode_switches_and_malformed_values_never_bypass_verification() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let manager = Arc::new(must_ok!(InMemoryPublicJwtKeyManager::new(), "signer"));
    let store = TokenStore::new_process_local_for_tests();
    let validator = TokenValidator::new(store.clone(), manager.clone())
        .with_issuer(Some("https://issuer.example".into()));
    let token = signed(manager.as_ref(), claims())?;
    store_jwt_access_token(&store, &token)?;
    check(&validator, &token, true, false).await;
    let parts: Vec<_> = token.split('.').collect();
    let bad = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode([0u8; 64])
    );
    for invalid in [&bad, "a.b", "a.b.c.d", "..", "a..b", "!.!.!"] {
        store_jwt_access_token(&store, invalid)?;
        assert!(
            store.try_verify_access_token(invalid)?.is_some(),
            "exact stored negative control"
        );
        check(&validator, invalid, false, false).await;
    }
    store_jwt_access_token(&store, "opaque")?;
    check(&validator, "opaque", true, false).await;
    let strict = validator.clone().with_jwt_access_tokens_enabled(true);
    assert!(strict
        .validate_bearer_token_with_meta("Bearer opaque")
        .is_err());
    assert!(strict
        .validate_bearer_token_with_meta_async("Bearer opaque".into())
        .await
        .is_err());
    assert_eq!(strict.introspect_token("opaque")["active"], true);
    check(&strict, &token, true, false).await;
    Ok(())
}

#[tokio::test]
async fn stored_jwt_invalid_claims_and_operational_verifier_failures_remain_distinct() -> TestResult
{
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let manager = Arc::new(must_ok!(InMemoryPublicJwtKeyManager::new(), "signer"));
    let store = TokenStore::new_process_local_for_tests();
    let validator = TokenValidator::new(store.clone(), manager.clone())
        .with_issuer(Some("https://issuer.example".into()))
        .with_jwt_leeway_secs(0);
    for (field, value) in [
        ("iss", json!("https://other.example")),
        ("aud", json!("other")),
        ("exp", json!(unix_epoch_now_secs() - 1)),
        ("jti", Value::Null),
    ] {
        let mut payload = claims();
        payload[field] = value;
        let token = signed(manager.as_ref(), payload)?;
        store_jwt_access_token(&store, &token)?;
        check(&validator, &token, false, false).await;
    }
    let token = signed(manager.as_ref(), claims())?;
    store_jwt_access_token(&store, &token)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let failed = validator
        .clone()
        .with_access_token_verifier(Arc::new(FailingVerifier(calls.clone())));
    check(&failed, &token, false, true).await;
    let count = calls.load(Ordering::SeqCst);
    assert!(count > 0);
    store_jwt_access_token(&store, "opaque")?;
    check(&failed, "opaque", true, false).await;
    assert_eq!(calls.load(Ordering::SeqCst), count);
    check(&validator, &token, true, false).await;
    Ok(())
}

#[tokio::test]
async fn stored_jwt_parser_policy_failure_is_operational_after_issuance_disabled() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let manager = Arc::new(must_ok!(InMemoryPublicJwtKeyManager::new(), "signer"));
    let store = TokenStore::new_process_local_for_tests();
    let token = signed(manager.as_ref(), claims())?;
    store_jwt_access_token(&store, &token)?;
    let validator = TokenValidator::new(store, manager);
    for surface in [
        aegaeon_jose::raw_json::RawJsonSurface::JwtAccessTokenHeader,
        aegaeon_jose::raw_json::RawJsonSurface::JwtAccessTokenPayload,
    ] {
        let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(surface);
        let _backend = EnvVarGuard::new(key, Some("future"));
        check(&validator, &token, false, true).await;
    }
    check(&validator, &token, true, false).await;
    Ok(())
}
