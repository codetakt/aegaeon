use super::super::test_support::{
    cleanup_test_environment as cleanup_test_dcr_environment, finish_test,
    sample_registered_client, setup_test_environment as setup_test_dcr_environment, test_app_state,
    test_pg_pool, TestEnvironment as TestDcrEnvironment, TestResult,
};
use axum::{
    body::{self, Body},
    http::{header, Method, Request, StatusCode},
    response::Response,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::io;
use tower::ServiceExt;

use crate::{
    client_registry::RegisteredClient,
    dcr_persistence::{create_dynamic_registration, preflight_dynamic_registration_schema},
};

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn dcr_configuration_read_requires_matching_registration_token() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool).await?;
    let result = read_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn dcr_configuration_update_rotates_token_and_preserves_client_id() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool).await?;
    let result = update_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn dcr_configuration_delete_invalidates_registration() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool).await?;
    let result = delete_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn dcr_configuration_rejects_token_owned_by_another_client() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool).await?;
    let result = ownership_mismatch_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn read_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let client = sample_registered_client("dcr-read-client");
    create_test_registration(pool, env, &client, "read-token").await?;
    let app = test_router(pool, env).await?;

    let response = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some("read-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await?;
    assert_eq!(body["client_id"], client.client_id);
    assert_eq!(body["redirect_uris"], json!(client.redirect_uris));

    let missing = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            None,
            None,
        )?)
        .await?;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let mismatched = app
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some("wrong-token"),
            None,
        )?)
        .await?;
    assert_eq!(mismatched.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn update_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let client = sample_registered_client("dcr-update-client");
    create_test_registration(pool, env, &client, "old-token").await?;
    let app = test_router(pool, env).await?;
    let updated_redirect_uri = "https://updated.example.com/callback";
    let update = json!({
        "client_id": client.client_id,
        "redirect_uris": [updated_redirect_uri],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid",
        "pkce_required": true
    });

    let response = app
        .clone()
        .oneshot(registration_request(
            Method::PUT,
            &client.client_id,
            Some("old-token"),
            Some(&update),
        )?)
        .await?;
    let update_status = response.status();
    let body = response_json(response).await?;
    assert_eq!(update_status, StatusCode::OK, "DEBUG body: {body}");
    assert_eq!(body["client_id"], client.client_id);
    assert_eq!(body["redirect_uris"], json!([updated_redirect_uri]));
    let new_token = body["registration_access_token"]
        .as_str()
        .ok_or_else(|| io::Error::other("update response missing registration_access_token"))?;
    assert_ne!(new_token, "old-token");

    let old_token_response = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some("old-token"),
            None,
        )?)
        .await?;
    assert_eq!(old_token_response.status(), StatusCode::UNAUTHORIZED);

    let new_token_response = app
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some(new_token),
            None,
        )?)
        .await?;
    assert_eq!(new_token_response.status(), StatusCode::OK);
    let read_body = response_json(new_token_response).await?;
    assert_eq!(read_body["client_id"], client.client_id);
    assert_eq!(read_body["redirect_uris"], json!([updated_redirect_uri]));
    Ok(())
}

async fn delete_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let client = sample_registered_client("dcr-delete-client");
    create_test_registration(pool, env, &client, "delete-token").await?;
    let app = test_router(pool, env).await?;

    let response = app
        .clone()
        .oneshot(registration_request(
            Method::DELETE,
            &client.client_id,
            Some("delete-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let read_after_delete = app
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some("delete-token"),
            None,
        )?)
        .await?;
    assert_eq!(read_after_delete.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn ownership_mismatch_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let owner = sample_registered_client("dcr-owner-client");
    let other = sample_registered_client("dcr-other-client");
    create_test_registration(pool, env, &owner, "owner-token").await?;
    create_test_registration(pool, env, &other, "other-token").await?;
    let app = test_router(pool, env).await?;

    let response = app
        .oneshot(registration_request(
            Method::GET,
            &other.client_id,
            Some("owner-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn create_test_registration(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    client: &RegisteredClient,
    registration_access_token: &str,
) -> TestResult {
    preflight_dynamic_registration_schema(pool).await?;
    create_dynamic_registration(
        pool,
        &env.issuer_host,
        client,
        &["code".to_string()],
        registration_access_token,
        "test-dcr-configuration-create",
    )
    .await?;
    Ok(())
}

fn registration_request(
    method: Method,
    client_id: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<Request<Body>, axum::http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("/register/{client_id}"))
        .header("x-request-id", "test-dcr-configuration-http");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    builder.body(Body::from(body.map_or_else(String::new, Value::to_string)))
}

async fn response_json(response: Response) -> TestResult<Value> {
    let bytes = body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn test_router(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult<axum::Router> {
    Ok(crate::web::router::build_router(
        test_app_state(pool.clone(), env).await?,
    ))
}
