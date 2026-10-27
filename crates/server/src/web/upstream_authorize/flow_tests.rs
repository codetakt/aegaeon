use super::flow::{build_upstream_authorize_redirect_response, store_upstream_authorize_request};
use super::{UpstreamAuthorizeContext, UpstreamAuthorizeInput};
use crate::web::{test_support, upstream_tests};
use axum::http::header;

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn upstream_authorize_query_rejection_preserves_transaction_store() -> test_support::TestResult
{
    let pool = test_support::test_pg_pool()
        .await?
        .ok_or("Postgres fixture required")?;
    let env = test_support::setup_test_environment(&pool).await?;
    let result = authorize_query_rejection_scenario(&pool, &env).await;
    test_support::finish_test(
        result,
        test_support::cleanup_test_environment(&pool, &env).await,
    )
}

async fn authorize_query_rejection_scenario(
    pool: &sqlx::PgPool,
    env: &test_support::TestEnvironment,
) -> test_support::TestResult {
    let state = test_support::test_app_state(pool.clone(), env).await?;
    let mut context = UpstreamAuthorizeContext {
        connection: upstream_tests::test_upstream_connection(
            env.environment_id,
            uuid::Uuid::new_v4(),
            "none",
            None,
        ),
        issuer: "https://issuer.example".to_string(),
        auth_method: "none".to_string(),
        profile: upstream_tests::base_profile(),
        active_logout_recovery_policy: None,
    };
    let input = UpstreamAuthorizeInput {
        return_to: None,
        scopes: vec!["openid".to_string()],
        scope: "openid".to_string(),
        acr: None,
        max_age: None,
    };
    let mut discovery = upstream_tests::base_discovery(&context.issuer)?;
    assert!(state
        .upstream
        .auth_store
        .process_local_state_tokens_for_test()?
        .is_empty());
    let valid_flow = store_upstream_authorize_request(
        &state,
        "example",
        &input,
        &context,
        &discovery,
        state.issuer.as_str(),
    )
    .await
    .map_err(|response| format!("valid authorize: {}", response.status()))?;
    let original = state
        .upstream
        .auth_store
        .process_local_state_tokens_for_test()?;
    assert_eq!(original.len(), 1);

    for (force_login, query) in [
        (false, "state=other"),
        (false, "%73tate=other"),
        (false, "client_id=client&%63lient_id=client"),
        (false, "redirect_uri=https%3A%2F%2Fevil.example%2Fcallback"),
        (false, "%72equest_uri=https%3A%2F%2Fevil.example%2Frequest"),
        (true, "prompt=none"),
        (true, "%70rompt=none"),
        (true, "prompt=login&%70rompt=login"),
    ] {
        context.active_logout_recovery_policy =
            force_login.then_some(crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin);
        discovery.authorization_endpoint = format!("https://issuer.example/authorize?{query}");
        let rejected = store_upstream_authorize_request(
            &state,
            "example",
            &input,
            &context,
            &discovery,
            state.issuer.as_str(),
        )
        .await
        .err()
        .ok_or_else(|| format!("query unexpectedly accepted: {query}"))?;
        assert_eq!(
            rejected.status(),
            axum::http::StatusCode::BAD_GATEWAY,
            "{query}"
        );
        assert!(
            !rejected.headers().contains_key(header::SET_COOKIE),
            "{query}"
        );
        assert_eq!(
            state
                .upstream
                .auth_store
                .process_local_state_tokens_for_test()?,
            original,
            "{query}"
        );
    }

    // The pre-existing valid transaction remains usable after every refusal.
    let discovery = upstream_tests::base_discovery(&context.issuer)?;
    let response = build_upstream_authorize_redirect_response(
        state.issuer.as_str(),
        &discovery,
        &context.connection.client_id,
        &input,
        &valid_flow,
        false,
    )
    .map_err(|response| format!("valid redirect: {}", response.status()))?;
    let url = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let cookie = response.headers()[header::SET_COOKIE].to_str()?;
    let (_, secret) = cookie
        .split(';')
        .next()
        .ok_or("cookie")?
        .split_once('=')
        .ok_or("cookie pair")?;
    let digest = aegaeon_crypto::hash::sha256_hex(secret.as_bytes());
    assert!(state
        .upstream
        .auth_store
        .try_consume_bound(&query["state"], &digest, &query["redirect_uri"])?
        .is_some());
    assert!(state
        .upstream
        .auth_store
        .process_local_state_tokens_for_test()?
        .is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn upstream_browser_binding_authorize_issues_independent_cookie_and_digest(
) -> test_support::TestResult {
    let pool = test_support::test_pg_pool()
        .await?
        .ok_or("Postgres fixture required")?;
    let env = test_support::setup_test_environment(&pool).await?;
    let result = authorize_browser_binding_scenario(&pool, &env).await;
    test_support::finish_test(
        result,
        test_support::cleanup_test_environment(&pool, &env).await,
    )
}

async fn authorize_browser_binding_scenario(
    pool: &sqlx::PgPool,
    env: &test_support::TestEnvironment,
) -> test_support::TestResult {
    let state = test_support::test_app_state(pool.clone(), env).await?;
    let connection = upstream_tests::test_upstream_connection(
        env.environment_id,
        uuid::Uuid::new_v4(),
        "none",
        None,
    );
    let context = UpstreamAuthorizeContext {
        connection,
        issuer: "https://issuer.example".to_string(),
        auth_method: "none".to_string(),
        profile: upstream_tests::base_profile(),
        active_logout_recovery_policy: None,
    };
    let input = UpstreamAuthorizeInput {
        return_to: Some("/continue".to_string()),
        scopes: vec!["openid".to_string()],
        scope: "openid".to_string(),
        acr: None,
        max_age: None,
    };
    let discovery = upstream_tests::base_discovery(&context.issuer)?;
    let mut cookie_names = Vec::new();
    for _ in 0..2 {
        let flow = store_upstream_authorize_request(
            &state,
            "example",
            &input,
            &context,
            &discovery,
            state.issuer.as_str(),
        )
        .await
        .map_err(|e| format!("store: {}", e.status()))?;
        let response = build_upstream_authorize_redirect_response(
            state.issuer.as_str(),
            &discovery,
            "client",
            &input,
            &flow,
            false,
        )
        .map_err(|e| format!("redirect: {}", e.status()))?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        let url = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let cookie = response.headers()[header::SET_COOKIE].to_str()?;
        let pair = cookie.split(';').next().ok_or("cookie")?;
        let (name, secret) = pair.split_once('=').ok_or("cookie pair")?;
        assert_eq!(secret.len(), 43);
        assert!(cookie.contains("; Secure; HttpOnly; SameSite=Lax"));
        assert!(!cookie.contains("Domain="));
        assert!(!url.as_str().contains(secret));
        assert_ne!(secret, query["state"]);
        assert_ne!(secret, query["nonce"]);
        let max_age: u64 = cookie
            .split("Max-Age=")
            .nth(1)
            .ok_or("max age")?
            .split(';')
            .next()
            .ok_or("max age")?
            .parse()?;
        assert!(max_age <= state.upstream.auth_store.ttl().as_secs());
        let digest = aegaeon_crypto::hash::sha256_hex(secret.as_bytes());
        let request = state
            .upstream
            .auth_store
            .try_consume_bound(&query["state"], &digest, &query["redirect_uri"])?
            .ok_or("bound record")?;
        assert_eq!(
            request.browser_binding_digest.as_deref(),
            Some(digest.as_str())
        );
        assert_ne!(request.code_verifier.as_deref(), Some(secret));
        assert_eq!(
            query["code_challenge"],
            crate::upstream::pkce_challenge(request.code_verifier.as_deref().ok_or("PKCE")?)
        );
        cookie_names.push(name.to_string());
    }
    assert_ne!(cookie_names[0], cookie_names[1]);
    Ok(())
}
