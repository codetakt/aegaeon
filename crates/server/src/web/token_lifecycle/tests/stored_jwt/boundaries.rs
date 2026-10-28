use super::*;

fn token_with_expiry(
    state: &AppState,
    key: &dyn KeyManager,
    exp: u64,
) -> TestResult<(AccessToken, BearerTokenMeta)> {
    let (mut access, _, mut meta) = grant(state, false, None);
    access.token = signed(
        key,
        &json!({"kid":key.key_id(),"alg":"EdDSA","typ":"at+jwt"}),
        &json!({"iss":state.issuer.as_str(),"sub":"subject","aud":meta.audience,
            "iat":900,"exp":exp,"jti":uuid::Uuid::new_v4().to_string()}),
    )?;
    meta.token_id.clone_from(&access.token);
    Ok((access, meta))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_stored_jwt_aliases_fail_closed_without_mutating_originals() -> TestResult {
    let mut fixture = Fixture::new(false).await?;
    let result = async {
        let key = InMemoryPublicJwtKeyManager::new()?;
        install(
            &mut fixture.state,
            vec![runtime_key(
                &key,
                RuntimeKeyStatus::Active,
                RuntimeKeyUsage::JwtAccessTokenSigning,
            )?],
            false,
        )?;
        fixture.state.tokens.validator = Arc::new(
            fixture
                .state
                .tokens
                .validator
                .as_ref()
                .clone()
                .with_now_for_tests(|| Ok(1000)),
        );
        for use_jwt in [false, true] {
            let (mut access, mut meta) = token_with_expiry(&fixture.state, &key, 1100)?;
            if !use_jwt {
                access.token = uuid::Uuid::new_v4().to_string();
                meta.token_id.clone_from(&access.token);
            }
            fixture
                .state
                .tokens
                .store
                .store_issued_grant(access.clone(), None, meta)?;
            let mut conn = fixture.connection()?;
            let original_key = fixture.key("access", &access.token);
            let original_meta = fixture.key("bearer", &access.token);
            let bytes: Vec<u8> = conn.get(&original_key)?;
            let meta_bytes: Vec<u8> = conn.get(&original_meta)?;
            let (other_jwt, _) = token_with_expiry(&fixture.state, &key, 1100)?;
            for alias in [
                uuid::Uuid::new_v4().to_string(),
                "malformed.jwt.value".into(),
                other_jwt.token,
            ] {
                let _: () = conn.set_ex(fixture.key("access", &alias), &bytes, 300)?;
                let _: () = conn.set_ex(fixture.key("bearer", &alias), &meta_bytes, 300)?;
                assert_eq!(
                    fixture
                        .state
                        .tokens
                        .store
                        .try_verify_access_token(&alias)?
                        .ok_or("alias control must reach the stored record")?
                        .token,
                    access.token
                );
                let validator = &fixture.state.tokens.validator;
                assert_eq!(validator.introspect_token(&alias), json!({"active":false}));
                let header = format!("Bearer {alias}");
                for outcome in [
                    validator.validate_bearer_token_with_meta(&header),
                    validator
                        .validate_bearer_token_with_meta_async(header)
                        .await,
                ] {
                    assert!(outcome.is_err_and(|e| !e.is_internal()));
                }
                for signed_response in [false, true] {
                    let (status, body) = introspection(
                        &fixture.state,
                        &alias,
                        &reader(&fixture.state, signed_response),
                        signed_response,
                    )
                    .await?;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(body, json!({"active":false}));
                }
                assert_eq!(conn.get::<_, Vec<u8>>(&original_key)?, bytes);
                assert_eq!(conn.get::<_, Vec<u8>>(&original_meta)?, meta_bytes);
                assert_eq!(
                    conn.get::<_, Vec<u8>>(fixture.key("access", &alias))?,
                    bytes
                );
            }
            inner(&fixture.state, &access.token, true).await?;
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_stored_jwt_expiration_is_exclusive_with_bounded_leeway() -> TestResult {
    let mut fixture = Fixture::new(false).await?;
    let result = async {
        let key = InMemoryPublicJwtKeyManager::new()?;
        install(
            &mut fixture.state,
            vec![runtime_key(
                &key,
                RuntimeKeyStatus::Active,
                RuntimeKeyUsage::JwtAccessTokenSigning,
            )?],
            false,
        )?;
        for leeway in [0, 2] {
            fixture.state.tokens.validator = Arc::new(
                fixture
                    .state
                    .tokens
                    .validator
                    .as_ref()
                    .clone()
                    .with_now_for_tests(|| Ok(1000))
                    .with_jwt_leeway_secs(leeway),
            );
            for exp in [997, 998, 999, 1000, 1001] {
                let (access, meta) = token_with_expiry(&fixture.state, &key, exp)?;
                fixture
                    .state
                    .tokens
                    .store
                    .store_issued_grant(access.clone(), None, meta)?;
                inner(&fixture.state, &access.token, exp + leeway > 1000).await?;
            }
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_stored_jwt_public_keys_survive_disabled_issuance() -> TestResult {
    let mut fixture = Fixture::new(false).await?;
    let result = async {
        assert!(!fixture.state.cfg.enable_jwt_access_tokens);
        fixture.state.keys.access_token = Arc::new(crate::kms::InMemoryKeyManager::new());
        let key = InMemoryPublicJwtKeyManager::new()?;
        let (access_jwt, _) = token_with_expiry(
            &fixture.state,
            &key,
            crate::util::now_unix_epoch_secs()? + 300,
        )?;
        for response_enabled in [false, true] {
            fixture.state.keys.jwt_introspection = if response_enabled {
                Some(Arc::new(InMemoryPublicJwtKeyManager::new()?))
            } else {
                None
            };
            for (status, expired, expected) in [
                (RuntimeKeyStatus::Active, false, true),
                (RuntimeKeyStatus::Retiring, false, true),
                (RuntimeKeyStatus::Retiring, true, false),
                (RuntimeKeyStatus::Next, false, false),
                (RuntimeKeyStatus::Revoked, false, false),
            ] {
                let mut runtime =
                    runtime_key(&key, status, RuntimeKeyUsage::JwtAccessTokenSigning)?;
                if expired {
                    runtime.retiring_expires_at_epoch_secs = Some(0);
                }
                install(&mut fixture.state, vec![runtime], false)?;
                assert_eq!(
                    fixture
                        .state
                        .tokens
                        .validator
                        .validate_stored_access_token_jwt(&access_jwt, None)
                        .is_ok(),
                    expected
                );
                let response = Router::new()
                    .route("/jwks", get(crate::web::metadata::jwks))
                    .with_state(fixture.state.clone())
                    .oneshot(Request::get("/jwks").body(Body::empty())?)
                    .await?;
                assert_eq!(response.status(), StatusCode::OK);
                let body: Value =
                    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
                let keys = body["keys"].as_array().ok_or("JWKS array")?;
                let published: Vec<_> = keys
                    .iter()
                    .filter(|jwk| jwk["kid"] == key.key_id())
                    .collect();
                assert_eq!(published.len(), usize::from(expected), "{body}");
                if expected {
                    let public = URL_SAFE_NO_PAD.decode(published[0]["x"].as_str().ok_or("x")?)?;
                    let (input, signature) =
                        access_jwt.token.rsplit_once('.').ok_or("JWT signature")?;
                    aegaeon_crypto::signature::verify_ed25519(
                        &public,
                        input.as_bytes(),
                        &URL_SAFE_NO_PAD.decode(signature)?,
                    )?;
                    for private in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                        assert!(published[0].get(private).is_none());
                    }
                }
                if let Some(response) = &fixture.state.keys.jwt_introspection {
                    assert!(keys.iter().any(|jwk| jwk["kid"] == response.key_id()));
                }
            }
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_stored_jwt_public_key_failure_refuses_partial_publication() -> TestResult {
    let mut fixture = Fixture::new(false).await?;
    let result = async {
        fixture.state.tokens.validator = Arc::new(
            fixture
                .state
                .tokens
                .validator
                .as_ref()
                .clone()
                .with_access_token_verifier(Arc::new(FaultVerifier(Arc::new(AtomicUsize::new(0))))),
        );
        assert!(fixture.state.keys.jwt_introspection.is_some());
        let response = Router::new()
            .route("/jwks", get(crate::web::metadata::jwks))
            .with_state(fixture.state.clone())
            .oneshot(Request::get("/jwks").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "temporarily_unavailable");
        assert!(body.get("keys").is_none());
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
