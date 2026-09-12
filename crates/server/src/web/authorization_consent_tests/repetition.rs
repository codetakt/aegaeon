//! Real consent routes and Redis redemption; authentication sessions are fixtures.
use super::*;

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn shared_redis_offline_consent_http_repeated_claim_profiles_and_refresh() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, _) = fixture(&pool, &env).await?;
        // Exercise a batch of 72 flows under supported configured bounds.
        // Default source-rate rejection has its own real Redis regression.
        Arc::make_mut(&mut state.cfg).database.authorization_admission =
            crate::config::AuthorizationAdmissionLimits::new(4096, 2048, 512)?;
        crate::web::token_exchange::tests::use_redis(&mut state)?;
        let oidc = state.oidc.config.as_ref().ok_or("OIDC configuration")?.as_ref().clone();
        state.tokens.issuer = Arc::new(crate::authcode::TokenIssuer::with_stores(Arc::clone(&state.keys.access_token), state.tokens.issuer.code_store.clone(), state.tokens.store.as_ref().clone())
            .with_issuer(state.issuer.to_string()).with_jwt_access_tokens_enabled(true).with_oidc(Some(oidc)));
        let mut codes = std::collections::HashSet::new();
        for claims in [
            serde_json::json!({"department":"engineering","role":"staff"}),
            serde_json::json!({"department":"engineering","role":"admin","employee_id":7}),
            serde_json::json!({"organization":{"z":3,"a":{"permissions":["read","write"]}},"role":"user"}),
        ] {
            let id = Uuid::new_v4();
            let subject = format!("repeated-{id}");
            sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES ($1,$2,$3,'ACTIVE')")
                .bind(id).bind(env.environment_id).bind(&subject).execute(&pool).await?;
            sqlx::query("INSERT INTO aegaeon.end_user_profiles(end_user_id,custom_claims) VALUES ($1,$2)")
                .bind(id).bind(&claims).execute(&pool).await?;
            let sid = state.browser_auth.auth_sessions.create(&subject,
                AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?), None, None, None).ok_or("session fixture")?;
            without_prompt(&state, &sid).await?;
            for scope in ["openid offline_access", SCOPE] {
                for iteration in 0..12 {
                    let uri = authorize_uri(&state, Some("consent"))?;
                    let mut fields: Vec<(String,String)> = url::form_urlencoded::parse(uri.split_once('?').ok_or("authorize query")?.1.as_bytes()).into_owned().collect();
                    for (key,value) in &mut fields { if key == "scope" { *value = scope.into(); } }
                    let uri = format!("/authorize?{}", serde_urlencoded::to_string(fields)?);
                    let (status, html) = send(&state, &sid, &uri, None, None).await?;
                    assert_eq!(status, StatusCode::OK, "authorize {iteration}: {html}");
                    let (status, body) = send(&state, &sid, "/auth/consent",
                        Some(vec![("transaction",transaction(&html)?),("decision","approve")]), Some(state.issuer.as_str())).await?;
                    assert_eq!(status, StatusCode::OK, "consent {iteration}: {body}");
                    let value: Value = serde_json::from_str(&body)?;
                    let code = value["code"].as_str().ok_or("fresh code")?;
                    assert!(codes.insert(code.to_owned()), "every iteration must redeem a new code");
                    let saved = state.tokens.issuer.code_store.try_get_code(code)?.ok_or("saved code")?;
                    assert_eq!(serde_json::to_value(saved.local_profile.ok_or("loaded profile")?.custom_claims)?, claims);
                    let issued = redeem(&state, &sid, &body).await?;
                    let refresh = issued["refresh_token"].as_str().ok_or("approved refresh")?;
                    let (status, body) = send(&state, &sid, "/token", Some(vec![
                        ("grant_type","refresh_token"),("client_id",CLIENT),("refresh_token",refresh)]), None).await?;
                    assert_eq!(status, StatusCode::OK, "refresh {iteration}: {body}");
                    let refreshed: Value = serde_json::from_str(&body)?;
                    for response in [&issued, &refreshed] {
                        assert_eq!(response["scope"], scope);
                        let access = response["access_token"].as_str().ok_or("access token")?;
                        let meta = state.tokens.store.try_get_bearer_meta(access)?.ok_or("saved access metadata")?;
                        assert_eq!(meta.user_id, subject);
                        assert_eq!(meta.audience, format!("{}/userinfo", state.issuer));
                    }
                }
            }
        }
        assert_eq!(codes.len(), 72);
        Ok(())
    }.await;
    let cleanup = async {
        sqlx::query("DELETE FROM aegaeon.end_users WHERE environment_id=$1")
            .bind(env.environment_id)
            .execute(&pool)
            .await?;
        cleanup_test_environment(&pool, &env).await
    }
    .await;
    finish_test(result, cleanup)
}
