use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_uri_and_opaque_targets_have_identical_lineage_requirements() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        let uri = "https://api.example/resource";
        // A single captured policy and the same source token authorize both
        // targets with identical mappings. Only target spelling differs.
        let policy = &mut Arc::make_mut(&mut state.cfg).token_exchange;
        policy.targets[0].resource_aliases.clear();
        policy
            .targets
            .push(crate::policy::token_exchange::ExchangeTarget {
                audience: uri.into(),
                resource_aliases: vec![uri.into()],
            });
        let mut rule = policy.rules[0].clone();
        rule.target_audience = uri.into();
        policy.rules.push(rule);
        policy.validate()?;
        state.tokens.issuer = Arc::new(
            crate::authcode::TokenIssuer::with_stores(
                Arc::clone(&state.keys.access_token),
                crate::authcode::AuthCodeStore::new_process_local_for_tests(),
                state.tokens.store.as_ref().clone(),
            )
            .with_issuer(env.issuer_url.clone())
            .with_oidc(state.oidc.config.as_deref().cloned())
            .with_token_exchange_policy(policy.clone())
            .with_jwt_access_tokens_enabled(true),
        );
        state.validate_subject_namespace().await?;
        compare_targets(&state, uri, true).await?;
        compare_targets(&state, uri, false).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn compare_targets(state: &AppState, uri: &str, offline: bool) -> TestResult {
    let req = serde_json::from_value(json!({"response_type":"code","client_id":CLIENT,
        "redirect_uri":"https://client.example.com/callback","resource":format!("{}/userinfo",state.issuer),
        "scope":if offline { SOURCE_SCOPE } else { "read write" },
        "state":uuid::Uuid::new_v4().to_string(),
        "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}))?;
    let (code, _) = issue_code(state, req, "exchange-user")?;
    let (status, initial) = request(
        state,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", CLIENT),
            ("redirect_uri", "https://client.example.com/callback"),
            ("code_verifier", VERIFIER),
        ],
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{initial}");
    assert_eq!(initial["refresh_token"].is_string(), offline);
    let source = initial["access_token"].as_str().ok_or("source")?;
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta(source)?
        .ok_or("source metadata")?;
    assert_eq!(meta.exchange_grant.is_some(), offline);
    for (selector, target) in [
        ("audience", "internal-api"),
        ("audience", uri),
        ("resource", uri),
    ] {
        let (status, value) = exchange(
            state,
            source,
            &[(selector, target), ("scope", "api.read")],
            true,
        )
        .await?;
        if offline {
            assert_eq!(status, StatusCode::OK, "{value}");
            let expected = if target == "internal-api" {
                "internal-api"
            } else {
                uri
            };
            assert_eq!(jwt(&value)?["aud"], expected);
            assert_eq!(value["scope"], "api.read");
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
            assert_eq!(value["error"], "invalid_target");
            assert!(value.get("access_token").is_none());
        }
    }
    Ok(())
}
