//! Exercise code-time scope ceilings through token, refresh and exchange HTTP
//! handlers. Registration changes use the runtime projection boundary here;
//! management authentication and browser authorization remain separate tests.
use super::*;

fn registration_scopes(state: &AppState, target_scopes: &[&str]) -> TestResult {
    let mut client = state.clients.try_get(CLIENT)?.ok_or("registered client")?;
    client.allowed_scopes = SOURCE_SCOPE.split(' ').map(str::to_owned).collect();
    client
        .allowed_scopes
        .extend(target_scopes.iter().map(|s| (*s).to_owned()));
    assert!(state.clients.try_update(client)?);
    Ok(())
}

async fn target_scope(
    state: &AppState,
    token: &str,
    scope: &str,
    allowed: bool,
) -> TestResult<Value> {
    let (status, body) = exchange(
        state,
        token,
        &[("audience", "internal-api"), ("scope", scope)],
        true,
    )
    .await?;
    if allowed {
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["scope"], scope);
        assert_eq!(jwt(&body)?["aud"], "internal-api");
    } else {
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_scope");
        assert!(body.get("access_token").is_none());
    }
    Ok(body)
}

fn approved_code(state: &AppState) -> TestResult<String> {
    let req = serde_json::from_value(json!({"response_type":"code","client_id":CLIENT,
        "redirect_uri":"https://client.example.com/callback",
        "resource":format!("{}/userinfo",state.issuer),"scope":SOURCE_SCOPE,
        "state":uuid::Uuid::new_v4().to_string(),
        "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}))?;
    Ok(issue_code(state, req, "exchange-user")?.0)
}

async fn redeem_code(state: &AppState, code: &str) -> TestResult<(StatusCode, Value)> {
    request(
        state,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", CLIENT),
            ("redirect_uri", "https://client.example.com/callback"),
            ("code_verifier", VERIFIER),
        ],
        true,
    )
    .await
}

async fn scenarios(state: &AppState) -> TestResult {
    registration_scopes(state, &["api.read"])?;
    let original = grant(state).await?;
    let source = original["access_token"].as_str().ok_or("source")?;
    let read = target_scope(state, source, "api.read", true).await?;
    target_scope(state, source, "api.write", false).await?;
    let metadata = state
        .tokens
        .store
        .try_get_bearer_meta(source)?
        .ok_or("metadata")?;
    let captured = metadata
        .exchange_grant
        .clone()
        .ok_or("captured scope ceiling")?;

    // Authorization happened before registration was broadened, even when code
    // redemption itself happens after the change.
    let code = approved_code(state)?;
    registration_scopes(state, &["api.read", "api.write"])?;
    target_scope(state, source, "api.write", false).await?;
    target_scope(state, source, "api.read", true).await?;
    target_scope(
        state,
        read["access_token"].as_str().ok_or("read token")?,
        "api.write",
        false,
    )
    .await?;
    let (status, redeemed) = redeem_code(state, &code).await?;
    assert_eq!(status, StatusCode::OK, "{redeemed}");
    target_scope(
        state,
        redeemed["access_token"].as_str().ok_or("redeemed")?,
        "api.write",
        false,
    )
    .await?;

    let (status, refreshed) = request(
        state,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT),
            (
                "refresh_token",
                original["refresh_token"].as_str().ok_or("refresh")?,
            ),
        ],
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let refreshed_source = refreshed["access_token"]
        .as_str()
        .ok_or("refreshed source")?;
    target_scope(state, refreshed_source, "api.write", false).await?;
    target_scope(state, refreshed_source, "api.read", true).await?;
    let retained = state
        .tokens
        .store
        .try_get_refresh_token(
            refreshed["refresh_token"]
                .as_str()
                .ok_or("rotated refresh")?,
        )?
        .ok_or("retained parent")?;
    assert_eq!(retained.exchange_grant, Some(captured));

    // A fresh authorization may use the expanded registration. Current
    // registration narrowing still restricts that newly authorized grant.
    let fresh = grant(state).await?;
    let fresh_source = fresh["access_token"].as_str().ok_or("fresh source")?;
    target_scope(state, fresh_source, "api.write", true).await?;
    registration_scopes(state, &["api.read"])?;
    target_scope(state, fresh_source, "api.write", false).await?;
    target_scope(state, fresh_source, "api.read", true).await?;
    registration_scopes(state, &["api.read", "api.write"])?;
    target_scope(state, fresh_source, "api.write", true).await?;
    target_scope(state, refreshed_source, "api.write", false).await?;
    Ok(())
}

async fn old_snapshot_requires_reauthorization(state: &AppState) -> TestResult {
    let current_code = approved_code(state)?;
    let mut old = state
        .tokens
        .issuer
        .code_store
        .try_get_code(&current_code)?
        .ok_or("code")?;
    let mut legacy = serde_json::to_value(old.exchange_grant.as_ref().ok_or("snapshot")?)?;
    legacy["version"] = json!(1);
    old.exchange_grant = Some(serde_json::from_value(legacy)?);
    old.code = uuid::Uuid::new_v4().to_string();
    old.state = None;
    state.tokens.issuer.code_store.store_code(old.clone())?;
    let (status, body) = redeem_code(state, &old.code).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
    let retained = state
        .tokens
        .issuer
        .code_store
        .try_get_code(&old.code)?
        .ok_or("old code retained")?;
    assert_eq!(serde_json::to_value(retained)?, serde_json::to_value(old)?);
    let (status, body) = redeem_code(state, &current_code).await?;
    assert_eq!(status, StatusCode::OK, "current snapshot: {body}");
    old_refresh_requires_reauthorization(state, &body).await
}

async fn old_refresh_requires_reauthorization(state: &AppState, body: &Value) -> TestResult {
    let refresh = body["refresh_token"].as_str().ok_or("refresh")?;
    let source = body["access_token"].as_str().ok_or("source")?;
    target_scope(state, source, "api.read", true).await?;
    let mut parent = state
        .tokens
        .store
        .try_get_refresh_token(refresh)?
        .ok_or("parent")?;
    let mut legacy = serde_json::to_value(parent.exchange_grant.as_ref().ok_or("snapshot")?)?;
    legacy["version"] = json!(1);
    parent.exchange_grant = Some(serde_json::from_value(legacy)?);
    state
        .tokens
        .store
        .try_replace_refresh_token_record(parent.clone())?;
    let mut meta = state
        .tokens
        .store
        .try_get_bearer_meta(source)?
        .ok_or("source metadata")?;
    meta.exchange_grant = parent.exchange_grant.clone();
    state.tokens.store.try_replace_bearer_meta_record(meta)?;
    let (status, denied) = exchange(state, source, &[("audience", "internal-api")], true).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    assert_eq!(denied["error"], "invalid_target");
    assert!(denied.get("access_token").is_none());
    let (status, body) = request(
        state,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT),
            ("refresh_token", refresh),
        ],
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
    let retained = state
        .tokens
        .store
        .try_get_refresh_token(refresh)?
        .ok_or("old parent retained")?;
    assert_eq!(
        serde_json::to_value(retained)?,
        serde_json::to_value(parent)?
    );
    Ok(())
}

async fn missing_snapshot_retains_only_legacy_exchange(state: &AppState) -> TestResult {
    registration_scopes(state, &[])?;
    let old = grant(state).await?;
    let source = old["access_token"].as_str().ok_or("legacy source")?;
    assert!(state
        .tokens
        .store
        .try_get_bearer_meta(source)?
        .ok_or("metadata")?
        .exchange_grant
        .is_none());
    registration_scopes(state, &["api.read", "api.write"])?;
    let audience = format!("{}/userinfo", state.issuer);
    let (status, body) = exchange(
        state,
        source,
        &[("audience", &audience), ("scope", "read")],
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "legacy control: {body}");
    let (status, body) = exchange(state, source, &[("audience", "internal-api")], true).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_target");
    assert!(body.get("access_token").is_none());
    let (status, fresh) = request(
        state,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT),
            (
                "refresh_token",
                old["refresh_token"].as_str().ok_or("legacy refresh")?,
            ),
        ],
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "legacy refresh: {fresh}");
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta(fresh["access_token"].as_str().ok_or("legacy child")?)?
        .ok_or("child metadata")?;
    assert!(meta.exchange_grant.is_none());
    let (status, body) = exchange(
        state,
        fresh["access_token"].as_str().ok_or("legacy child")?,
        &[("audience", "internal-api")],
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_target");
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn shared_redis_exchange_client_scope_expansion_cannot_authorize_existing_grants(
) -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        use_redis(&mut state)?;
        scenarios(&state).await?;
        old_snapshot_requires_reauthorization(&state).await?;
        missing_snapshot_retains_only_legacy_exchange(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
