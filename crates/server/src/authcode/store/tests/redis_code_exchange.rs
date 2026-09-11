mod lease;

use super::*;
use crate::authcode::token::TokenIssuer;
use crate::authcode::types::{TokenRequest, TokenResponse};
use crate::end_user_profiles::OidcProfileClaims;
use crate::kms::InMemoryKeyManager;

fn redis_url() -> Result<String, String> {
    std::env::var("AEGAEON_TEST_REDIS_URL")
        .map_err(|_| "AEGAEON_TEST_REDIS_URL is required; this test must execute Redis".to_string())
}

fn request(code: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code.to_string()),
        client_id: "test-client".to_string(),
        client_secret: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: None,
        request_object_claims: None,
    }
}

fn invalid_code(response: Result<TokenResponse, String>) -> bool {
    match response {
        Ok(TokenResponse::Error { error, .. }) => error == "invalid_grant",
        Err(error) => error == "Invalid or expired code",
        Ok(TokenResponse::Success { .. }) => false,
    }
}

fn issuer_with_code(url: &str) -> Result<(TokenIssuer, String), String> {
    let code_store = redis_auth_code_store_for_test(url);
    let issuer = TokenIssuer::with_stores(
        Arc::new(InMemoryKeyManager::new()),
        code_store.clone(),
        redis_token_store_for_test(url),
    );
    let mut code = make_test_code(None, None);
    code.scope = Some("read".to_string());
    code.code_challenge = Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string());
    code.code_challenge_method = Some("S256".to_string());
    Ok((issuer, code_store.store_code(code)?))
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_rejects_record_for_another_code() -> StoreTestResult {
    let url = redis_url()?;
    let (issuer, code_str) = issuer_with_code(&url)?;
    let context = issuer
        .code_store
        .redis_commit_context(&code_str)
        .ok_or_else(|| "Redis context missing".to_string())?;
    let mut stored = issuer
        .code_store
        .try_get_code(&code_str)?
        .ok_or_else(|| "stored code missing".to_string())?;
    stored.code = "a-different-authorization-code".to_string();
    let payload = serde_json::to_string(&stored).map_err(|err| err.to_string())?;
    let mut conn = redis::Client::open(url.as_str())
        .and_then(|client| client.get_connection())
        .map_err(|err| err.to_string())?;
    redis::cmd("SET")
        .arg(context.code_key)
        .arg(payload)
        .arg("XX")
        .arg("KEEPTTL")
        .query::<()>(&mut conn)
        .map_err(|err| err.to_string())?;
    assert!(
        invalid_code(issuer.exchange_code_for_tokens(request(&code_str), None)),
        "mismatched storage identity must not issue tokens"
    );
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_checks_bindings_before_consuming() -> StoreTestResult {
    let url = redis_url()?;
    let (issuer, code_str) = issuer_with_code(&url)?;
    for field in ["client", "redirect", "pkce"] {
        let mut req = request(&code_str);
        match field {
            "client" => req.client_id = "other-client".to_string(),
            "redirect" => req.redirect_uri = Some("https://other.example/callback".to_string()),
            _ => req.code_verifier = Some("incorrect-verifier".to_string()),
        }
        assert!(matches!(
            issuer.exchange_code_for_tokens(req, None)?,
            TokenResponse::Error { .. }
        ));
        assert!(issuer.code_store.try_get_code(&code_str)?.is_some());
    }
    assert!(matches!(
        issuer.exchange_code_for_tokens(request(&code_str), None)?,
        TokenResponse::Success { .. }
    ));
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_concurrent_requests_publish_once() -> StoreTestResult {
    let url = redis_url()?;
    let (issuer, code_str) = issuer_with_code(&url)?;
    let issuer = Arc::new(issuer);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let issuer = Arc::clone(&issuer);
            let barrier = Arc::clone(&barrier);
            let req = request(&code_str);
            std::thread::spawn(move || {
                barrier.wait();
                issuer.exchange_code_for_tokens(req, None)
            })
        })
        .collect();
    let mut successes = 0;
    for worker in workers {
        match worker
            .join()
            .map_err(|_| "exchange worker panicked".to_string())?
        {
            Ok(TokenResponse::Success { .. }) => successes += 1,
            rejected => assert!(invalid_code(rejected)),
        }
    }
    assert_eq!(successes, 1);
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_rejects_expired_storage_key() -> StoreTestResult {
    let url = redis_url()?;
    let (issuer, code_str) = issuer_with_code(&url)?;
    let context = issuer
        .code_store
        .redis_commit_context(&code_str)
        .ok_or_else(|| "Redis context missing".to_string())?;
    let mut conn = redis::Client::open(url.as_str())
        .and_then(|client| client.get_connection())
        .map_err(|err| err.to_string())?;
    // Expire in the past, avoiding a scheduling-dependent sleep.
    redis::cmd("PEXPIREAT")
        .arg(context.code_key)
        .arg(1)
        .query::<()>(&mut conn)
        .map_err(|err| err.to_string())?;
    assert!(invalid_code(
        issuer.exchange_code_for_tokens(request(&code_str), None)
    ));
    Ok(())
}

fn exchange_legacy_json(asynchronous: bool) -> StoreTestResult {
    let url = redis_url()?;
    let code_store = redis_auth_code_store_for_test(&url);
    let token_store = redis_token_store_for_test(&url);
    let issuer = TokenIssuer::with_stores(
        Arc::new(InMemoryKeyManager::new()),
        code_store.clone(),
        token_store.clone(),
    );
    let mut conn = redis::Client::open(url.as_str())
        .and_then(|client| client.get_connection())
        .map_err(|err| err.to_string())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|err| err.to_string())?;

    for claims in [
        serde_json::json!({}),
        serde_json::json!({"department": "engineering"}),
        serde_json::json!({"z": 1, "a": 2, "m": 3}),
        serde_json::json!({"https://example.com/claims": {"roles": ["reader"], "z": 1}, "a": 2}),
    ] {
        let mut code = make_test_code(None, None);
        code.scope = Some("read".to_string());
        code.code_challenge = Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string());
        code.code_challenge_method = Some("S256".to_string());
        code.local_profile = Some(OidcProfileClaims {
            custom_claims: serde_json::from_value(claims).map_err(|err| err.to_string())?,
            ..OidcProfileClaims::default()
        });
        let code_str = code_store.store_code(code.clone())?;
        let context = code_store
            .redis_commit_context(&code_str)
            .ok_or_else(|| "Redis commit context is required".to_string())?;
        // A valid legacy JSON representation with deterministic ordering/spacing
        // differences. Do not rely on a random HashMap iteration order to fail.
        let value = serde_json::to_value(&code).map_err(|err| err.to_string())?;
        let raw = serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?;
        let decoded: AuthorizationCode =
            serde_json::from_str(&raw).map_err(|err| err.to_string())?;
        assert_eq!(
            serde_json::to_value(&decoded).map_err(|err| err.to_string())?,
            value
        );
        assert_ne!(
            serde_json::to_string(&decoded).map_err(|err| err.to_string())?,
            raw
        );
        redis::cmd("SET")
            .arg(&context.code_key)
            .arg(&raw)
            .arg("XX")
            .arg("KEEPTTL")
            .query::<()>(&mut conn)
            .map_err(|err| err.to_string())?;

        let exchange = || {
            if asynchronous {
                runtime.block_on(
                    issuer.exchange_code_for_tokens_bound_with_grant_policy_async(
                        request(&code_str),
                        None,
                        None,
                        true,
                        false,
                    ),
                )
            } else {
                issuer.exchange_code_for_tokens_bound_with_grant_policy(
                    request(&code_str),
                    None,
                    None,
                    true,
                    false,
                )
            }
        };
        let response = exchange()?;
        let TokenResponse::Success { access_token, .. } = response else {
            return Err(format!("valid legacy JSON must redeem: {response:?}"));
        };
        assert!(token_store
            .try_verify_access_token(&access_token)?
            .is_some());
        assert!(code_store.try_get_code(&code_str)?.is_none());
        assert!(invalid_code(exchange()));
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_preserves_legacy_json_sync() -> StoreTestResult {
    exchange_legacy_json(false)
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_preserves_legacy_json_async() -> StoreTestResult {
    exchange_legacy_json(true)
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_partial_write_error_does_not_enable_retry() -> StoreTestResult {
    let url = redis_url()?;
    let code_store = redis_auth_code_store_for_test(&url);
    let token_store = redis_token_store_for_test(&url);
    let mut code = make_test_code(None, None);
    let suffix = uuid::Uuid::new_v4().to_string();
    code.user_id = format!("partial-error-{suffix}");
    code.scope = Some("read".to_string());
    let raw = serde_json::to_string(&code).map_err(|err| err.to_string())?;
    let code_str = code_store.store_code(code.clone())?;
    let mut conn = redis::Client::open(url.as_str())
        .and_then(|client| client.get_connection())
        .map_err(|err| err.to_string())?;
    let index = format!(
        "token-store:v3:{{tokens}}:subject-bearer:{}",
        token_store_key_digest(&code.user_id)
    );
    redis::cmd("SET")
        .arg(&index)
        .arg("wrong-type")
        .query::<()>(&mut conn)
        .map_err(|err| err.to_string())?;
    let commit = |token: &str| {
        let mut access = make_access_token(token);
        access.user_id.clone_from(&code.user_id);
        let mut meta = make_bearer_meta(token, None);
        meta.user_id.clone_from(&code.user_id);
        token_store.store_issued_authorization_code_grant(AuthorizationCodeGrantCommit::new(
            code_store.clone(),
            code_str.clone(),
            raw.clone(),
            access,
            None,
            meta,
            None,
        ))
    };
    let first = format!("partial-{suffix}-first");
    let failed = commit(&first)
        .err()
        .ok_or_else(|| "wrong-type index must fail the real Lua".to_string())?;
    assert!(failed.contains("WRONGTYPE"), "unexpected failure: {failed}");
    // Redis script errors leave earlier writes intact. Repair only our synthetic
    // index before checking that the same authorization code cannot publish again.
    redis::cmd("DEL")
        .arg(&index)
        .query::<()>(&mut conn)
        .map_err(|err| err.to_string())?;
    assert!(token_store.try_verify_access_token(&first)?.is_some());
    assert!(
        code_store.try_get_code(&code_str)?.is_none(),
        "a failed publication must retire its code"
    );
    let second = format!("partial-{suffix}-second");
    assert_eq!(
        commit(&second)
            .err()
            .ok_or_else(|| "retry must be rejected".to_string())?,
        AUTHORIZATION_CODE_GRANT_CODE_MISSING
    );
    assert!(token_store.try_verify_access_token(&second)?.is_none());
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_offline_target_survives_storage_and_refresh() -> StoreTestResult {
    let url = redis_url()?;
    let signing_key = crate::oidc::OidcSigningKey::from_rsa_pem(
        "offline-target-test-key".to_string(),
        include_str!("../../../../tests/fixtures/rsa2048-private.pk8.pem"),
    )
    .map_err(|err| err.to_string())?;
    let oidc = crate::oidc::OidcConfig {
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
    };
    let code_store = redis_auth_code_store_for_test(&url);
    let token_store = redis_token_store_for_test(&url);
    let issuer = TokenIssuer::with_stores(
        Arc::new(InMemoryKeyManager::new()),
        code_store.clone(),
        token_store.clone(),
    )
    .with_oidc(Some(oidc));
    let runtime = tokio::runtime::Runtime::new().map_err(|err| err.to_string())?;
    for scope in [
        "openid offline_access",
        "openid profile email offline_access",
    ] {
        // This is a granted-scope fixture at the issuer boundary, not a consent UI test.
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut code = make_test_code(None, Some(&nonce));
        code.scope = Some(scope.to_string());
        code.auth_session_id = Some(nonce);
        let code_str = code_store.store_code(code)?;
        let response = runtime.block_on(
            issuer.exchange_code_for_tokens_bound_with_grant_policy_async(
                request(&code_str),
                None,
                None,
                true,
                true,
            ),
        )?;
        let TokenResponse::Success {
            access_token,
            refresh_token: Some(refresh),
            ..
        } = response
        else {
            return Err(format!("offline Redis grant must succeed: {response:?}"));
        };
        let target = "https://auth.example.com/userinfo";
        assert_eq!(
            token_store
                .try_get_bearer_meta(&access_token)?
                .ok_or_else(|| "metadata missing".to_string())?
                .audience,
            target
        );
        let saved = token_store
            .try_get_refresh_token(&refresh)?
            .ok_or_else(|| "refresh record missing".to_string())?;
        assert!(
            saved.resource.is_none(),
            "requested resource remains distinct from resolved target"
        );
        assert_eq!(
            saved
                .target_context
                .ok_or_else(|| "original target context missing".to_string())?
                .audience,
            target
        );
        let response =
            runtime.block_on(issuer.refresh_access_token_bound_async(refresh, None, None, None))?;
        let TokenResponse::Success {
            access_token,
            refresh_token: Some(successor),
            ..
        } = response
        else {
            return Err(format!("offline Redis refresh must succeed: {response:?}"));
        };
        assert_eq!(
            token_store
                .try_get_bearer_meta(&access_token)?
                .ok_or_else(|| "metadata missing".to_string())?
                .audience,
            target
        );
        assert_eq!(
            token_store
                .try_get_refresh_token(&successor)?
                .ok_or_else(|| "successor missing".to_string())?
                .target_context
                .ok_or_else(|| "preserved target context missing".to_string())?
                .audience,
            target
        );
    }
    Ok(())
}
