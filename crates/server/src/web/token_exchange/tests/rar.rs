//! HTTP admission regression: rejected RAR parameters must not consume a grant.
use super::*;

async fn scenarios(state: &AppState) -> TestResult {
    let req = serde_json::from_value(json!({"response_type":"code","client_id":CLIENT,
        "redirect_uri":"https://client.example.com/callback","scope":SOURCE_SCOPE,"resource":format!("{}/userinfo", state.issuer),
        "state":uuid::Uuid::new_v4().to_string(),"code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}))?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(req, "rar-control".into())?;
    let code_fields = [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT),
        ("code", code.as_str()),
        ("redirect_uri", "https://client.example.com/callback"),
        ("code_verifier", VERIFIER),
    ];
    for raw in ["[]", "null", "{", r#"[{"type":"payment","amount":"1"}]"#] {
        let mut fields = code_fields.to_vec();
        fields.push(("authorization_details", raw));
        let (status, body) = request(state, &fields, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_authorization_details");
        assert!(body.get("access_token").is_none());
    }
    let (status, issued) = request(state, &code_fields, true).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "code was consumed on RAR refusal: {issued}"
    );
    let refresh = issued["refresh_token"].as_str().ok_or("refresh token")?;
    let refresh_fields = [
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT),
        ("refresh_token", refresh),
    ];
    let source = issued["access_token"].as_str().ok_or("access token")?;
    for raw in ["[]", "null", "{", r#"[{"type":"payment","amount":"1"}]"#] {
        let mut fields = refresh_fields.to_vec();
        fields.push(("authorization_details", raw));
        let (status, body) = request(state, &fields, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_authorization_details");
        assert!(
            !state
                .tokens
                .store
                .try_get_refresh_token(refresh)?
                .ok_or("saved refresh")?
                .rotated
        );
        let (status, body) = exchange(
            state,
            source,
            &[("audience", "internal-api"), ("authorization_details", raw)],
            true,
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_authorization_details");
        assert!(body.get("access_token").is_none());
    }
    let (status, body) = exchange(
        state,
        source,
        &[
            ("audience", "internal-api"),
            ("authorization_details", ""),
            ("extension", "ignored"),
        ],
        true,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "empty/unknown parameter control: {body}"
    );
    let (status, body) = request(state, &refresh_fields, true).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "refresh was consumed on RAR refusal: {body}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn shared_redis_token_rar_refusal_does_not_consume_grants() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        use_redis(&mut state)?;
        scenarios(&state).await?;
        stored_constraints(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

// Inject legacy records at the store boundary: supported HTTP endpoints no
// longer issue RAR grants. Validate refusal with a live non-RAR control first.
async fn stored_constraints(state: &AppState) -> TestResult {
    for legacy in [false, true] {
        let mut state = state.clone();
        if legacy {
            state.tokens.issuer = Arc::new(
                crate::authcode::TokenIssuer::with_stores(
                    Arc::clone(&state.keys.access_token),
                    state.tokens.issuer.code_store.clone(),
                    state.tokens.store.as_ref().clone(),
                )
                .with_issuer(state.issuer.to_string())
                .with_token_exchange_policy(TokenExchangePolicy::default())
                .with_jwt_access_tokens_enabled(true),
            );
        }
        let issued = grant(&state).await?;
        let token = issued["access_token"].as_str().ok_or("source")?;
        let target = if legacy {
            format!("{}/userinfo", state.issuer)
        } else {
            "internal-api".into()
        };
        let selector = [("audience", target.as_str())];
        let (status, body) = exchange(&state, token, &selector, true).await?;
        assert_eq!(status, StatusCode::OK, "non-RAR control: {body}");
        let mut meta = state
            .tokens
            .store
            .try_get_bearer_meta(token)?
            .ok_or("metadata")?;
        meta.authorization_details = Some(json!([{"type":"payment","actions":["read"]}]));
        state
            .tokens
            .store
            .try_replace_bearer_meta_record(meta.clone())?;
        let (status, body) = exchange(&state, token, &selector, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(
            body["error_description"],
            "subject_token contains unsupported authorization details"
        );
        assert!(body.get("access_token").is_none());
        assert!(state.tokens.store.try_verify_access_token(token)?.is_some());
        let context = crate::authcode::TokenPolicyContext {
            requested_scopes: &[],
            resource_audience: Some(&meta.audience),
            sender_dpop_jkt: None,
            sender_mtls_fingerprint: None,
        };
        assert!(state
            .tokens
            .validator
            .enforce_with_meta_async(&meta, context)
            .await
            .is_err());
        assert_eq!(
            state
                .tokens
                .store
                .try_get_bearer_meta(token)?
                .ok_or("retained metadata")?
                .authorization_details,
            meta.authorization_details
        );
    }
    Ok(())
}
