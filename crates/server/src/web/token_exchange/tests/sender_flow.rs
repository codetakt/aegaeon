use super::*;

async fn flow(state: &AppState) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let proof = signed_dpop_with_key(&key)?;
    let jkt =
        crate::util::compute_dpop_jkt_from_proof_with_max_len(&proof, 8192).ok_or("thumbprint")?;
    let initial = grant_with_proof(state, Some(&proof)).await?;
    assert_eq!(initial["token_type"], "DPoP");
    let refresh = initial["refresh_token"].as_str().ok_or("refresh")?;
    let fields = [
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT),
        ("refresh_token", refresh),
    ];
    for proof in [None, Some(signed_dpop_proof()?)] {
        let (status, body) = request_with_proof(state, &fields, true, proof.as_deref()).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "refresh binding: {body}");
        assert!(
            !state
                .tokens
                .store
                .try_get_refresh_token(refresh)?
                .ok_or("refresh retained")?
                .rotated
        );
    }
    let (status, refreshed) =
        request_with_proof(state, &fields, true, Some(&signed_dpop_with_key(&key)?)).await?;
    assert_eq!(status, StatusCode::OK, "refresh: {refreshed}");
    assert_eq!(refreshed["token_type"], "DPoP");
    for body in [&initial, &refreshed] {
        assert_eq!(jwt(body)?["cnf"], json!({"jkt":jkt}));
        let token = body["access_token"].as_str().ok_or("access")?;
        assert_eq!(
            state
                .tokens
                .store
                .try_verify_access_token(token)?
                .ok_or("saved access")?
                .token_type,
            "DPoP"
        );
    }
    let mut subject = refreshed["access_token"]
        .as_str()
        .ok_or("subject")?
        .to_string();
    for _ in 0..2 {
        let fields = [
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("client_id", CLIENT),
            ("subject_token", subject.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", "internal-api"),
        ];
        let (status, body) =
            request_with_proof(state, &fields, true, Some(&signed_dpop_proof()?)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "different key: {body}");
        let (status, body) =
            request_with_proof(state, &fields, true, Some(&signed_dpop_with_key(&key)?)).await?;
        assert_eq!(status, StatusCode::OK, "same-key exchange: {body}");
        assert_eq!(body["token_type"], "DPoP");
        assert_eq!(jwt(&body)?["cnf"], json!({"jkt":jkt}));
        assert_eq!(jwt(&body)?["sub"], jwt(&initial)?["sub"]);
        subject = body["access_token"]
            .as_str()
            .ok_or("exchanged token")?
            .to_string();
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis; proof admission uses the HTTP test mock"]
async fn shared_redis_token_exchange_dpop_code_refresh_reexchange() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        use_redis(&mut state)?;
        flow(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis; proof admission uses the HTTP test mock"]
async fn shared_redis_bound_refresh_enforced_when_policy_option_disabled() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        sqlx::query("UPDATE aegaeon.oauth_profiles SET enforce_refresh_sender_binding = false WHERE environment_id = $1")
            .bind(env.environment_id).execute(&pool).await?;
        Arc::make_mut(&mut state.cfg).security_policy = state.cfg.security_policy
            .with_sender_binding_enforcement(false);
        use_redis(&mut state)?;
        assert!(!state.cfg.security_policy.enforce_sender_binding());
        let enforcing_profiles: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.oauth_profiles WHERE environment_id = $1 AND enforce_refresh_sender_binding")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(enforcing_profiles, 0);
        // Valid issuance, missing/wrong-key refusals without consumption, then
        // same-key refresh and exchange controls, under the disabled options.
        flow(&state).await
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
