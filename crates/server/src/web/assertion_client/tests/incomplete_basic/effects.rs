use super::*;

async fn public_code_survives(state: &AppState) -> TestResult {
    let request = serde_json::from_value(json!({"response_type":"code", "client_id":PUBLIC,
        "redirect_uri":REDIRECT,"scope":"api.read","code_challenge":CHALLENGE,
        "code_challenge_method":"S256"}))?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(request, "basic-admission-user".into())?;
    let f = [
        ("grant_type", "authorization_code"),
        ("client_id", PUBLIC),
        ("code", &code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];
    let before = stored_values(state)?;
    for auth in incomplete_headers() {
        reject(state, "/token", &f, Some(&auth)).await?;
        assert!(
            before == stored_values(state)?,
            "refused Basic consumed public grant"
        );
    }
    let body = successful_response(state, "/token", &f, None).await?;
    let token = body["access_token"].as_str().ok_or("access token")?;
    assert!(state.tokens.store.try_verify_access_token(token)?.is_some());
    reject_with(
        state,
        "/token",
        &f,
        None,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await
}

async fn live_token_survives(state: &AppState) -> TestResult {
    let body = successful_response(
        state,
        "/token",
        &borrowed(&password_fields("/token", BASIC)),
        Some(&basic()),
    )
    .await?;
    let token = body["access_token"].as_str().ok_or("live access token")?;
    let f = [("token", token), ("client_id", BASIC)];
    let before = stored_values(state)?;
    for auth in incomplete_headers() {
        for path in ["/introspect", "/revoke"] {
            reject(state, path, &f, Some(&auth)).await?;
            assert!(
                before == stored_values(state)?,
                "refused Basic changed live token state"
            );
            assert!(state.tokens.store.try_verify_access_token(token)?.is_some());
        }
    }
    let (status, headers, body) = send_response(
        state,
        "/introspect",
        &serde_urlencoded::to_string(f)?,
        Some(&basic()),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], true);
    assert_client_challenge("/introspect", &headers, false)?;
    successful_response(state, "/revoke", &f, Some(&basic())).await?;
    assert!(state.tokens.store.try_verify_access_token(token)?.is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn incomplete_basic_preserves_public_code_and_live_token_until_corrected_retry() -> TestResult
{
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        public_code_survives(&state).await?;
        live_token_survives(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
