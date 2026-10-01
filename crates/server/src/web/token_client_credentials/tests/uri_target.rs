use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_client_credentials_uri_default_and_resource_alias_use_canonical_audience() -> TestResult
{
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let initial = fixture(&pool, &env, true, false).await?;
        let uri = "https://api.example/canonical";
        let mut configured = policy(true)?;
        configured.token_exchange.targets[0].audience = uri.into();
        configured.client_credentials.resource_servers[0].target_audience = uri.into();
        configured.client_credentials.rules[0].target_audience = uri.into();
        configured.client_credentials.rules[0].default_target = true;
        install_policy(&pool, &env, &configured).await?;
        let state = reload(&initial, &env).await?;
        for selector in [None, Some(("resource", ALIAS)), Some(("audience", uri))] {
            let mut params = vec![("grant_type", "client_credentials")];
            if let Some(selector) = selector {
                params.push(selector);
            }
            let (status, value) = request(&state, "/token", CALLER, SECRET, &params).await?;
            assert_eq!(status, StatusCode::OK, "{value}");
            let token = value["access_token"].as_str().ok_or("JWT access token")?;
            let claims: Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(token.split('.').nth(1).ok_or("JWT payload")?)?,
            )?;
            assert_eq!(claims["aud"], uri);
            assert_eq!(claims["client_id"], CALLER);
            let meta = state
                .tokens
                .store
                .try_get_bearer_meta(token)?
                .ok_or("stored token")?;
            assert_eq!(meta.audience, uri);
            assert_eq!(introspect(&state, RS, token).await?["active"], true);
        }
        configured.client_credentials.rules[0].default_target = false;
        install_policy(&pool, &env, &configured).await?;
        let state = reload(&state, &env).await?;
        for selector in [
            None,
            Some(("resource", "https://unknown.example/resource")),
            Some(("audience", "closed")),
        ] {
            let mut params = vec![("grant_type", "client_credentials")];
            if let Some(selector) = selector {
                params.push(selector);
            }
            let (status, value) = request(&state, "/token", CALLER, SECRET, &params).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
            assert_eq!(value["error"], "invalid_target");
            assert!(value.get("access_token").is_none());
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
