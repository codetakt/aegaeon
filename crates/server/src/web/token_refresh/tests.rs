//! HTTP refresh regressions start with an already-authorized offline grant.
//! They do not establish how offline consent was obtained.
use super::super::test_support::{
    cleanup_test_environment, finish_test, sample_registered_client, setup_test_environment,
    test_app_state, TestEnvironment, TestResult,
};
use super::super::AppState;
use crate::authcode::types::{
    AccessToken, BearerTokenMeta, BearerTokenMetaInput, RefreshTargetContext, RefreshToken,
    RefreshTokenInput,
};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    routing::post,
    Extension, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sqlx::PgPool;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tower::ServiceExt;
use uuid::Uuid;

const GRANTED_SCOPE: &str = "openid profile email offline_access";
const CLIENT_ID: &str = "refresh-scope-client";

async fn fixture(pool: &PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    let mut client = sample_registered_client(CLIENT_ID);
    client.allowed_scopes = GRANTED_SCOPE.split(' ').map(str::to_owned).collect();
    client.allowed_grant_types.push("refresh_token".to_string());
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".to_string()],
        "scope-test-registration-token",
        "scope-test-registration",
    )
    .await?;
    sqlx::query(
        "UPDATE aegaeon.oauth_profiles SET allowed_grant_types = $1 WHERE environment_id = $2",
    )
    .bind(vec!["authorization_code", "refresh_token"])
    .bind(env.environment_id)
    .execute(pool)
    .await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    // Use the supported Bearer profile; DPoP validation has separate regressions.
    Arc::make_mut(&mut state.cfg)
        .security_policy
        .sender_constrained = crate::policy::SenderConstraint::None;
    state.keys.access_token = Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?);
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            Arc::clone(&state.keys.access_token),
            crate::authcode::AuthCodeStore::new_process_local_for_tests(),
            state.tokens.store.as_ref().clone(),
        )
        .with_issuer(env.issuer_url.clone())
        .with_jwt_access_tokens_enabled(true),
    );
    Ok(state)
}

fn seed_grant(state: &AppState) -> TestResult<String> {
    let mut refresh = RefreshToken::new(RefreshTokenInput {
        scope: Some(GRANTED_SCOPE.to_string()),
        ..RefreshTokenInput::new(CLIENT_ID.to_string(), "scope-user".to_string())
    });
    let audience = format!("{}/userinfo", state.issuer);
    refresh.target_context = Some(RefreshTargetContext {
        version: 1,
        audience: audience.clone(),
        token_issuer: Some(state.issuer.to_string()),
        oidc_issuer: None,
    });
    let token = format!("initial-{}", Uuid::new_v4());
    let now = SystemTime::now();
    let access = AccessToken {
        token: token.clone(),
        token_type: "Bearer".to_string(),
        client_id: CLIENT_ID.to_string(),
        user_id: refresh.user_id.clone(),
        scope: refresh.scope.clone(),
        expires_in: 300,
        created_at: now,
        cnf: None,
    };
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: token,
        client_id: CLIENT_ID.to_string(),
        user_id: refresh.user_id.clone(),
        granted_scopes: GRANTED_SCOPE.split(' ').map(str::to_owned).collect(),
        audience,
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: Some(0),
        acr: None,
        issued_at: now,
        expires_at: now + Duration::from_secs(300),
        refresh_parent: Some(refresh.token.clone()),
    });
    let value = refresh.token.clone();
    state
        .tokens
        .store
        .store_issued_grant(access, Some(refresh), meta)?;
    Ok(value)
}

async fn request(
    state: &AppState,
    refresh: &str,
    scope: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT_ID),
        ("refresh_token", refresh),
    ];
    if let Some(scope) = scope {
        params.push(("scope", scope));
    }
    let body = serde_urlencoded::to_string(params)?;
    let app = Router::new()
        .route("/token", post(super::super::token_endpoint::token))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        )))))
        .with_state(state.clone());
    let response = app
        .oneshot(
            Request::post("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

fn check_grant(state: &AppState, body: &Value, expected_scope: &str) -> TestResult<String> {
    let access = body["access_token"]
        .as_str()
        .ok_or("access_token missing")?;
    let refresh = body["refresh_token"]
        .as_str()
        .ok_or("refresh_token missing")?;
    let payload = access.split('.').nth(1).ok_or("JWT payload missing")?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
    let expected: BTreeSet<_> = expected_scope.split(' ').collect();
    assert_eq!(
        claims["scope"]
            .as_str()
            .ok_or("JWT scope missing")?
            .split(' ')
            .collect::<BTreeSet<_>>(),
        expected,
        "JWT scope"
    );
    assert_eq!(claims["aud"], format!("{}/userinfo", state.issuer));
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta(access)?
        .ok_or("metadata missing")?;
    assert_eq!(
        meta.granted_scopes
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(meta.audience, format!("{}/userinfo", state.issuer));
    let saved = state
        .tokens
        .store
        .try_get_refresh_token(refresh)?
        .ok_or("replacement missing")?;
    assert_eq!(
        saved.scope.as_deref(),
        Some(GRANTED_SCOPE),
        "replacement RT grant must stay unchanged"
    );
    // RFC 6749 permits omission when response scope equals the request's scope.
    if let Some(scope) = body.get("scope") {
        assert_eq!(
            scope
                .as_str()
                .ok_or("response scope must be a string")?
                .split(' ')
                .collect::<BTreeSet<_>>(),
            expected
        );
    }
    Ok(refresh.to_string())
}

async fn flow(state: &AppState, scope: Option<&str>) -> TestResult {
    let refresh = seed_grant(state)?;
    let (status, body) = request(state, &refresh, scope).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let next = check_grant(state, &body, scope.unwrap_or(GRANTED_SCOPE))?;
    assert_ne!(next, refresh);
    assert!(
        state
            .tokens
            .store
            .try_get_refresh_token(&refresh)?
            .ok_or("previous missing")?
            .rotated
    );
    let (status, body) = request(state, &next, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    check_grant(state, &body, GRANTED_SCOPE)?;
    Ok(())
}

async fn rejected_scopes(state: &AppState, scopes: &[&str]) -> TestResult {
    for scope in scopes {
        let refresh = seed_grant(state)?;
        let (status, body) = request(state, &refresh, Some(scope)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "scope {scope:?}: {body}");
        assert_eq!(body["error"], "invalid_scope");
        assert!(body.get("access_token").is_none());
        assert!(
            !state
                .tokens
                .store
                .try_get_refresh_token(&refresh)?
                .ok_or("previous missing")?
                .rotated
        );
        let (status, body) = request(state, &refresh, None).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "rejected scope must leave RT usable: {body}"
        );
        check_grant(state, &body, GRANTED_SCOPE)?;
    }
    Ok(())
}

async fn run(case: &str) -> TestResult {
    // Explicitly ignored without infrastructure; when selected, missing DB must fail.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        match case {
            "omitted" => flow(&state, None).await,
            "subset" => flow(&state, Some("profile")).await,
            "reordered" => flow(&state, Some("email offline_access profile openid")).await,
            "expansion" => rejected_scopes(&state, &["admin", "openid admin", "OpenID"]).await,
            "syntax" => {
                rejected_scopes(
                    &state,
                    &[
                        "",
                        " openid",
                        "openid ",
                        "openid  profile",
                        "openid\tprofile",
                        "openid\nprofile",
                        "openid\u{a0}profile",
                        "open\"id",
                        "open\\id",
                        "openid openid",
                    ],
                )
                .await
            }
            _ => Err("unknown test case".into()),
        }
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn refresh_scope_http_omission_preserves_grant() -> TestResult {
    run("omitted").await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn refresh_scope_http_subset_preserves_replacement_and_target() -> TestResult {
    run("subset").await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn refresh_scope_http_reordering_preserves_grant() -> TestResult {
    run("reordered").await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn refresh_scope_http_expansion_does_not_consume_grant() -> TestResult {
    run("expansion").await
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn refresh_scope_http_malformed_does_not_consume_grant() -> TestResult {
    run("syntax").await
}
