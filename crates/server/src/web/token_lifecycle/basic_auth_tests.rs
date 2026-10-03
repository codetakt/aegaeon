use super::super::test_support::{
    cleanup_test_environment, finish_test, sample_registered_client, setup_test_environment,
    test_app_state, test_pg_pool, TestEnvironment, TestResult,
};
use super::super::AppState;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    Extension,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use std::net::SocketAddr;
use tower::ServiceExt;

const COMPLEX_WIRE: &str = "client%3A+%2B%25%26%3D%C3%A9:secret%3A+%2B%25%26%3D%E9%9B%AA";

async fn fixture(pool: &sqlx::PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed = $1 WHERE environment_id = $2")
        .bind(vec!["client_secret_basic", "client_secret_post"]).bind(env.environment_id).execute(pool).await?;
    for (id, secret, method) in [
        ("client: +%&=é", "secret: +%&=雪", "client_secret_basic"),
        ("literal+client", "literal+secret", "client_secret_basic"),
        ("once%2Bclient", "once%25secret", "client_secret_basic"),
        ("generated_ID-1", "secret_ID-2", "client_secret_basic"),
        ("post-client", "secret", "client_secret_post"),
    ] {
        let mut client = sample_registered_client(id);
        client.token_endpoint_auth_method = method.into();
        client.client_secret = Some(secret.into());
        crate::dcr_persistence::create_dynamic_registration(
            pool,
            &env.issuer_host,
            &client,
            &["code".into()],
            &format!("basic-test-registration-{id}"),
            "basic-test",
        )
        .await?;
    }
    test_app_state(pool.clone(), env).await
}

async fn introspect(
    state: &AppState,
    auth: &str,
    extra_secret: bool,
    duplicate_header: bool,
) -> TestResult<(StatusCode, Value)> {
    let mut request = Request::post("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, auth);
    if duplicate_header {
        request = request.header(header::AUTHORIZATION, auth);
    }
    let body = if extra_secret {
        "token=unknown&client_secret=stray"
    } else {
        "token=unknown"
    };
    let app = super::super::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let response = app.oneshot(request.body(Body::from(body))?).await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?,
    ))
}

async fn exercise(state: &AppState) -> TestResult {
    for wire in [
        COMPLEX_WIRE,
        "literal%2Bclient:literal%2Bsecret",
        "once%252Bclient:once%2525secret",
        "generated_ID-1:secret_ID-2",
    ] {
        let auth = format!("bAsIc {}", STANDARD.encode(wire));
        let (status, body) = introspect(state, &auth, false, false).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["active"], false);
    }
    for wire in [
        "literal+client:literal+secret",
        "once%2Bclient:once%25secret",
        "literal%2Bclient:literal+secret",
        "once%252Bclient:once%25secret",
        "client%3A+%2B%25%26%3D%C3%A9:wrong",
        "generated_ID-1:%",
        "generated_ID-1:%C3%28",
        "missing-colon",
        "post-client:secret",
    ] {
        let auth = format!("Basic {}", STANDARD.encode(wire));
        let (status, body) = introspect(state, &auth, false, false).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"], "invalid_client");
    }
    for (auth, extra_secret, duplicate_header) in [
        ("Basic %%%".to_string(), false, false),
        (
            format!("Basic {}", STANDARD.encode(COMPLEX_WIRE)),
            true,
            false,
        ),
        (
            format!("Basic {}", STANDARD.encode(COMPLEX_WIRE)),
            false,
            true,
        ),
    ] {
        let (status, body) = introspect(state, &auth, extra_secret, duplicate_header).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"], "invalid_client");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn oauth_basic_http_introspection_uses_decoded_logical_credentials() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        exercise(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
