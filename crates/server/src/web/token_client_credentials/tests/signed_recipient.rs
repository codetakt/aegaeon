use super::signed_introspection::{signed_response_for, verified_response_for};
use super::*;

async fn signed_active(
    state: &AppState,
    token: &str,
    caller: &str,
    secret: &str,
    active: bool,
) -> TestResult {
    let compact = signed_response_for(state, token, caller, secret).await?;
    let body = verified_response_for(state, &compact, caller)?;
    if active {
        assert_eq!(body["token_introspection"]["active"], true);
        assert_eq!(body["token_introspection"]["aud"], TARGET);
    } else {
        assert_eq!(body["token_introspection"], json!({"active":false}));
    }
    Ok(())
}

async fn issue(state: &AppState) -> TestResult<String> {
    let (status, body) = request(
        state,
        "/token",
        CALLER,
        SECRET,
        &[("grant_type", "client_credentials"), ("audience", TARGET)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body["access_token"].as_str().ok_or("token missing")?.into())
}

async fn signed_fixture(
    pool: &PgPool,
    env: &TestEnvironment,
) -> TestResult<(AppState, PolicyDocument)> {
    let mut state = fixture(pool, env, false, true).await?;
    state.keys.jwt_introspection = Some(Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?));
    let mut document = policy(false)?;
    document.jwt_introspection_enabled = true;
    install_policy(pool, env, &document).await?;
    Ok((reload(&state, env).await?, document))
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn signed_recipient_cc_requires_retained_reader_not_owner_or_audience_equality() -> TestResult
{
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (state, mut document) = signed_fixture(&pool, &env).await?;
        let token = issue(&state).await?;
        assert_eq!(introspect(&state, CALLER, &token).await?["active"], true);
        signed_active(&state, &token, CALLER, SECRET, false).await?;
        signed_active(&state, &token, RS, RS_SECRET, true).await?;
        for caller in [TARGET, "unrelated-client"] {
            signed_active(&state, &token, caller, credential(caller), false).await?;
        }
        // A mapping for CC does not grant the same reader access to another grant.
        let access = crate::authcode::types::AccessToken::new(
            CALLER.into(),
            "subject".into(),
            Some("api.read".into()),
            300,
        );
        let meta = crate::authcode::types::BearerTokenMeta::new(
            crate::authcode::types::BearerTokenMetaInput {
                token_id: access.token.clone(),
                client_id: CALLER.into(),
                user_id: "subject".into(),
                granted_scopes: vec!["api.read".into()],
                audience: TARGET.into(),
                sender_binding: None,
                authorization_details: None,
                auth_time_epoch_secs: None,
                acr: None,
                issued_at: access.created_at,
                expires_at: access.created_at + std::time::Duration::from_secs(300),
                refresh_parent: None,
            },
        );
        state
            .tokens
            .store
            .store_issued_grant(access.clone(), None, meta)?;
        signed_active(&state, &access.token, RS, RS_SECRET, false).await?;
        assert_eq!(
            introspect(&state, CALLER, &access.token).await?["active"],
            true
        );
        // Explicit owner-as-reader configuration is retained in the newly issued grant.
        document.client_credentials.resource_servers[0]
            .introspection_clients
            .push(CALLER.into());
        install_policy(&pool, &env, &document).await?;
        let changed = reload(&state, &env).await?;
        signed_active(&changed, &token, RS, RS_SECRET, false).await?;
        let fresh = issue(&changed).await?;
        signed_active(&changed, &fresh, CALLER, SECRET, true).await?;
        signed_active(&changed, &fresh, RS, RS_SECRET, true).await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn signed_recipient_cc_reregistration_cannot_reuse_retained_reader_identity() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (state, _) = signed_fixture(&pool, &env).await?;
        let token = issue(&state).await?;
        signed_active(&state, &token, RS, RS_SECRET, true).await?;
        replace_registration(&pool, &env, RS).await?;
        let changed = reload(&state, &env).await?;
        signed_active(
            &changed,
            &token,
            RS,
            "replacement-private-fixture-secret",
            false,
        )
        .await?;
        let fresh = issue(&changed).await?;
        signed_active(
            &changed,
            &fresh,
            RS,
            "replacement-private-fixture-secret",
            true,
        )
        .await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
