//! Shared loader state supports both authenticated grants and authorization requests.
use super::*;
use axum::routing::get;
use std::collections::BTreeMap;

async fn exercise_loaded_state(state: &AppState) -> TestResult {
    let (status, issued) = request(
        state,
        "/token",
        CALLER,
        SECRET,
        &[("grant_type", "client_credentials"), ("audience", TARGET)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["access_token"]
        .as_str()
        .ok_or("expected issued access token")?;
    let visible = introspect(state, RS, token).await?;
    assert_eq!(visible["active"], true);
    assert_eq!(visible["client_id"], CALLER);
    assert_eq!(visible["aud"], TARGET);
    assert_eq!(visible["scope"], "api.read");

    let client = state.clients.try_get(CALLER)?.ok_or("caller missing")?;
    let redirect = client.redirect_uris.first().ok_or("redirect missing")?;
    let query = serde_urlencoded::to_string([
        ("client_id", CALLER),
        ("redirect_uri", redirect.as_str()),
        ("response_type", "code"),
        ("scope", "api.read"),
        ("iss", state.issuer.as_str()),
        ("state", "mixed-client-authority"),
        ("prompt", "none"),
        (
            "code_challenge",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ),
        ("code_challenge_method", "S256"),
    ])?;
    let app = Router::new()
        .route("/authorize", get(crate::web::authorize_endpoint::authorize))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::web::runtime_authority_guard::runtime_authority_guard_middleware,
        ))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12455,
        )))))
        .with_state(state.clone());
    let response = app
        .oneshot(Request::get(format!("/authorize?{query}")).body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = url::Url::parse(
        response
            .headers()
            .get(header::LOCATION)
            .ok_or("expected protocol error redirect")?
            .to_str()?,
    )?;
    let expected = url::Url::parse(redirect)?;
    assert_eq!(location.origin(), expected.origin());
    assert_eq!(location.path(), expected.path());
    let values = location
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        values.get("error").map(String::as_str),
        Some("login_required")
    );
    assert_eq!(
        values.get("state").map(String::as_str),
        Some("mixed-client-authority")
    );
    assert_eq!(
        values.get("iss").map(String::as_str),
        Some(state.issuer.as_str())
    );
    assert!(!values.contains_key("code"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL"]
async fn client_credentials_and_authorization_share_loaded_runtime() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required; this test must not silently skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env, false, false).await?;
        exercise_loaded_state(&state).await?;

        let mut next_policy = policy(false)?;
        next_policy.oidc_enabled = true;
        next_policy.oidc_require_nonce = false;
        seed_oidc_configuration(&pool, &env, next_policy, "cc-mixed-authority").await?;
        let reloaded = reload(&state, &env).await?;
        assert!(reloaded.oidc.config.is_some());
        exercise_loaded_state(&reloaded).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
