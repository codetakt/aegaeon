use super::*;
use crate::authcode::types::{
    AuthorizationCode, AuthorizationCodeInput, TokenRequest, TokenResponse,
};
use crate::authcode::{AuthCodeStore, TokenIssuer, TokenValidator};

fn tokens(response: TokenResponse) -> TestResult<(String, String)> {
    match response {
        TokenResponse::Success {
            access_token,
            refresh_token: Some(refresh_token),
            ..
        } => Ok((access_token, refresh_token)),
        other => Err(format!("unexpected issuance response: {other:?}").into()),
    }
}

async fn issue(
    fixture: &Fixture,
    issuer: &TokenIssuer,
    codes: &AuthCodeStore,
) -> TestResult<(String, String)> {
    let audience = crate::resource_audience::protected_resource(fixture.state.issuer.as_str());
    let code = AuthorizationCode::new(AuthorizationCodeInput {
        scope: Some("read offline_access".into()),
        resource: Some(audience.clone()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
        code_challenge_method: Some("S256".into()),
        ..AuthorizationCodeInput::new(
            OWNER.into(),
            "subject".into(),
            Some("https://client.example/callback".into()),
        )
    });
    let request = TokenRequest {
        grant_type: "authorization_code".into(),
        code: Some(codes.store_code(code)?),
        redirect_uri: Some("https://client.example/callback".into()),
        client_id: OWNER.into(),
        client_secret: None,
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into()),
        resource: Some(audience),
        request_object_claims: None,
    };
    tokens(
        issuer
            .exchange_code_for_tokens_bound_with_grant_policy_async(request, None, None, true, true)
            .await?,
    )
}

async fn revoke_http(state: &AppState, token: &str, caller: &str) -> TestResult<StatusCode> {
    Ok(router(state)
        .oneshot(
            Request::post("/revoke")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(format!("{caller}:{SECRET}"))),
                )
                .body(Body::from(serde_urlencoded::to_string([("token", token)])?))?,
        )
        .await?
        .status())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_refresh_grant_family_opaque_and_jwt_resource_and_introspection() -> TestResult
{
    for jwt in [false, true] {
        let mut fixture = Fixture::new(false).await?;
        let key: Arc<dyn crate::kms::KeyManager> =
            Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?);
        fixture.state.keys.access_token = key.clone();
        fixture.state.tokens.validator = Arc::new(
            TokenValidator::with_policy(
                fixture.state.tokens.store.as_ref().clone(),
                key.clone(),
                fixture.state.cfg.security_policy,
            )
            .with_jwt_access_tokens_enabled(jwt)
            .with_issuer(Some(fixture.state.issuer.to_string())),
        );
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
        let result = async {
            for revoke_middle in [false, true] {
                let (a1, r1) = issue(&fixture, &issuer, &codes).await?;
                assert_eq!(a1.split('.').count() == 3, jwt);
                let (other, _) = issue(&fixture, &issuer, &codes).await?;
                let (a2, r2) = tokens(
                    issuer
                        .refresh_access_token_bound_async(r1.clone(), None, None, None)
                        .await?,
                )?;
                let (a3, r3) = tokens(
                    issuer
                        .refresh_access_token_bound_async(r2.clone(), None, None, None)
                        .await?,
                )?;
                for access in [&a1, &a2, &a3] {
                    observe(&fixture.state, access, true).await?;
                }
                assert_eq!(
                    revoke_http(&fixture.state, &r2, OTHER).await?,
                    StatusCode::UNAUTHORIZED
                );
                observe(&fixture.state, &a3, true).await?;
                assert_eq!(
                    revoke_http(&fixture.state, &a2, OWNER).await?,
                    StatusCode::OK
                );
                observe(&fixture.state, &a2, false).await?;
                observe(&fixture.state, &a1, true).await?;
                observe(&fixture.state, &a3, true).await?;
                let revoked = if revoke_middle { &r2 } else { &r3 };
                assert_eq!(
                    revoke_http(&fixture.state, revoked, OWNER).await?,
                    StatusCode::OK
                );
                assert_eq!(
                    revoke_http(&fixture.state, revoked, OWNER).await?,
                    StatusCode::OK
                );
                for access in [&a1, &a2, &a3] {
                    observe(&fixture.state, access, false).await?;
                }
                for refresh in [&r1, &r2, &r3] {
                    assert!(fixture
                        .state
                        .tokens
                        .store
                        .try_get_refresh_token(refresh)?
                        .is_none());
                }
                observe(&fixture.state, &other, true).await?;
            }
            let (a1, r1) = issue(&fixture, &issuer, &codes).await?;
            let (a2, _) = tokens(
                issuer
                    .refresh_access_token_bound_async(r1.clone(), None, None, None)
                    .await?,
            )?;
            let replay = issuer
                .refresh_access_token_bound_async(r1, None, None, None)
                .await;
            assert!(matches!(replay, Err(_) | Ok(TokenResponse::Error { .. })));
            observe(&fixture.state, &a1, false).await?;
            observe(&fixture.state, &a2, false).await?;
            Ok(())
        }
        .await;
        fixture.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_refresh_grant_introspection_hides_grant_storage_errors_from_unrelated_caller(
) -> TestResult {
    let fixture = Fixture::new(false).await?;
    let result = async {
        let (access, refresh, meta) = grant(&fixture.state, true, None);
        fixture
            .state
            .tokens
            .store
            .store_issued_grant(access.clone(), refresh, meta)?;
        let meta = fixture
            .state
            .tokens
            .store
            .try_get_bearer_meta(&access.token)?
            .ok_or("metadata missing")?;
        let reference = meta.refresh_grant.ok_or("grant missing")?;
        let mut conn = fixture.connection()?;
        let key = fixture.key("refresh-grant:v1", &reference.id);
        let _: usize = conn.del(&key)?;
        let _: usize = conn.lpush(&key, "wrong-type")?;
        for jwt in [false, true] {
            let before = super::failures::metrics()?;
            let (status, body) = introspection(&fixture.state, &access.token, OWNER, jwt).await?;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["error"], "temporarily_unavailable");
            assert!(body.get("active").is_none());
            assert_eq!(super::failures::metrics()?, before);
            let (status, body) = introspection(&fixture.state, &access.token, OTHER, jwt).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, json!({"active":false}));
        }
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn shared_redis_refresh_grant_revocation_cleanup_failure_commits_denial_before_http_error(
) -> TestResult {
    let fixture = Fixture::new(false).await?;
    let result = async {
        let (access, refresh, meta) = grant(&fixture.state, true, None);
        let refresh = refresh.ok_or("refresh missing")?;
        fixture.state.tokens.store.store_issued_grant(
            access.clone(),
            Some(refresh.clone()),
            meta,
        )?;
        let mut conn = fixture.connection()?;
        let index = fixture.key("refresh-children", &refresh.token);
        let _: () = conn.set(&index, "{")?;
        assert_eq!(
            revoke_http(&fixture.state, &refresh.token, OTHER).await?,
            StatusCode::UNAUTHORIZED
        );
        observe(&fixture.state, &access.token, true).await?;
        assert_eq!(
            revoke_http(&fixture.state, &refresh.token, OWNER).await?,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            fixture
                .state
                .tokens
                .store
                .try_get_bearer_meta(&access.token)?
                .is_some(),
            "physical cleanup failed"
        );
        observe(&fixture.state, &access.token, false).await?;
        let _: usize = conn.del(&index)?;
        assert_eq!(
            revoke_http(&fixture.state, &refresh.token, OWNER).await?,
            StatusCode::OK
        );
        observe(&fixture.state, &access.token, false).await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
