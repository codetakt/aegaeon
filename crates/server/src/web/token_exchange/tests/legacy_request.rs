//! HTTP exchange and stored lineage; code approval is seeded through the issuer.
use super::*;

async fn issue_without_parent(
    state: &AppState,
    scope: &str,
    resource: Option<&str>,
    issue_refresh: bool,
) -> TestResult<String> {
    let req = serde_json::from_value(json!({
        "response_type":"code", "client_id":CLIENT,
        "redirect_uri":"https://client.example.com/callback", "resource":resource,
        "scope":scope, "state":uuid::Uuid::new_v4().to_string(),
        "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method":"S256"
    }))?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(req, "exchange-user".into())?;
    let req = serde_json::from_value(json!({
        "grant_type":"authorization_code", "client_id":CLIENT, "code":code,
        "redirect_uri":"https://client.example.com/callback", "code_verifier":VERIFIER
    }))?;
    let response = state
        .tokens
        .issuer
        .exchange_code_for_tokens_bound_with_grant_policy_async(
            req,
            None,
            None,
            true,
            issue_refresh,
        )
        .await?;
    let crate::authcode::types::TokenResponse::Success {
        access_token,
        refresh_token: None,
        ..
    } = response
    else {
        return Err(format!("expected no-parent issuance: {response:?}").into());
    };
    Ok(access_token)
}

async fn scenarios(state: &AppState) -> TestResult {
    let source_audience = format!("{}/userinfo", state.issuer);
    for (scope, issue_refresh) in [("read", true), (SOURCE_SCOPE, false)] {
        let token =
            issue_without_parent(state, scope, Some(&source_audience), issue_refresh).await?;
        let meta = state
            .tokens
            .store
            .try_get_bearer_meta(&token)?
            .ok_or("missing metadata")?;
        assert!(meta.refresh_parent.is_none());
        assert!(meta.exchange_grant.is_none());
        let (status, body) = exchange(
            state,
            &token,
            &[("audience", &source_audience), ("scope", "read")],
            true,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "same-audience exchange: {body}");
        assert_eq!(jwt(&body)?["aud"], source_audience);
        for selectors in [
            vec![("resource", source_audience.as_str())],
            vec![("audience", "internal-api")],
        ] {
            let (status, body) = exchange(state, &token, &selectors, true).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["error"], "invalid_target");
            assert!(body.get("access_token").is_none());
        }
        let (status, body) = exchange(
            state,
            &token,
            &[("audience", &source_audience), ("scope", "read")],
            true,
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "rejection must preserve source: {body}"
        );
    }
    // This audience equals client_id, so an omitted selector must not use its fallback.
    let token = issue_without_parent(state, "read", None, false).await?;
    for selectors in [vec![], vec![("audience", "")]] {
        let (status, body) = exchange(state, &token, &selectors, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_target");
        assert!(body.get("access_token").is_none());
    }
    let (status, body) = exchange(state, &token, &[("audience", CLIENT)], true).await?;
    assert_eq!(status, StatusCode::OK, "explicit matching audience: {body}");
    assert_eq!(jwt(&body)?["aud"], CLIENT);
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn token_exchange_no_parent_and_legacy_selector_contract() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async { scenarios(&fixture(&pool, &env).await?).await }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn shared_redis_token_exchange_no_parent_and_legacy_selector_contract() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        use_redis(&mut state)?;
        scenarios(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
