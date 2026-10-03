//! Local router fixtures retain production transport and database admission guards.
use crate::web::{test_support::*, AppState};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
    response::Response,
    Extension,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{io, net::SocketAddr, sync::Arc};
use tower::ServiceExt;

// Literal paths deliberately exercise the externally specified locator.
const CANONICAL: &str = "/.well-known/oauth-protected-resource/resource";
const LEGACY: &str = "/.well-known/oauth-protected-resource";

async fn fixture() -> TestResult<(PgPool, TestEnvironment, AppState)> {
    let pool = test_pg_pool().await?.ok_or_else(|| {
        io::Error::other("protected-resource router tests require AEGAEON_DATABASE_URL")
    })?;
    let env = setup_test_environment(&pool).await?;
    let state = test_app_state(pool.clone(), &env).await?;
    Ok((pool, env, state))
}

async fn request(state: &AppState, method: Method, uri: &str) -> TestResult<Response> {
    Ok(crate::web::router::build_router(state.clone())
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            42049,
        )))))
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::HOST, "untrusted.example")
                .header("forwarded", "host=untrusted.example;proto=https")
                .body(Body::empty())?,
        )
        .await?)
}

async fn document(response: Response) -> TestResult<Value> {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 16 * 1024).await?,
    )?)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
async fn protected_resource_locator_preserves_trusted_identity_and_capabilities() -> TestResult {
    let (pool, env, mut state) = fixture().await?;
    let result: TestResult = async {
        for mtls in [false, true] {
            update_test_policy(&mut state, |policy| policy.mtls_enabled = mtls).await?;
            for terminal_slash in [false, true] {
                // A trusted AppState helper edge, not a claim that managed issuer
                // configuration accepts path-based deployments.
                state.issuer = Arc::new(format!(
                    "{}{}",
                    env.issuer_url,
                    if terminal_slash { "/" } else { "" }
                ));
                let body = document(request(&state, Method::GET, CANONICAL).await?).await?;
                assert_eq!(body["resource"], format!("{}/resource", env.issuer_url));
                assert_eq!(
                    body["authorization_servers"],
                    json!([state.issuer.as_str()])
                );
                assert_eq!(body["scopes_supported"], json!(["read"]));
                assert_eq!(body["bearer_methods_supported"], json!(["header"]));
                assert_eq!(body["dpop_signing_alg_values_supported"], json!(["EdDSA"]));
                assert_eq!(body["tls_client_certificate_bound_access_tokens"], mtls);
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
async fn protected_resource_locator_redirect_is_fixed_and_followable() -> TestResult {
    let (pool, env, state) = fixture().await?;
    let result: TestResult = async {
        for uri in [
            LEGACY.to_string(),
            format!("{LEGACY}?next=https%3A%2F%2Funtrusted.example"),
        ] {
            let response = request(&state, Method::GET, &uri).await?;
            assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
            assert_eq!(response.headers()[header::LOCATION], CANONICAL);
            let location = response.headers()[header::LOCATION].to_str()?.to_string();
            assert!(to_bytes(response.into_body(), 1024).await?.is_empty());
            let body = document(request(&state, Method::GET, &location).await?).await?;
            assert_eq!(body["resource"], format!("{}/resource", env.issuer_url));
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
async fn protected_resource_locator_rejects_other_paths_and_preserves_methods() -> TestResult {
    let (pool, env, state) = fixture().await?;
    let result: TestResult = async {
        for path in [
            format!("{LEGACY}/userinfo"),
            format!("{LEGACY}/other"),
            format!("{LEGACY}/"),
            format!("{CANONICAL}/"),
        ] {
            assert_eq!(
                request(&state, Method::GET, &path).await?.status(),
                StatusCode::NOT_FOUND
            );
        }
        for (path, expected) in [
            (CANONICAL, StatusCode::OK),
            (LEGACY, StatusCode::PERMANENT_REDIRECT),
        ] {
            assert_eq!(
                request(&state, Method::POST, path).await?.status(),
                StatusCode::METHOD_NOT_ALLOWED
            );
            let head = request(&state, Method::HEAD, path).await?;
            assert_eq!(head.status(), expected);
            if path == LEGACY {
                assert_eq!(head.headers()[header::LOCATION], CANONICAL);
            } else {
                assert_eq!(head.headers()[header::CONTENT_TYPE], "application/json");
            }
            assert!(to_bytes(head.into_body(), 16 * 1024).await?.is_empty());
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
async fn protected_resource_locator_retains_transport_and_runtime_guards() -> TestResult {
    let (pool, env, state) = fixture().await?;
    let result: TestResult = async {
        let mut transport_state = state.clone();
        transport_state.transport = crate::middleware::TransportSecurity::new(
            crate::config::TransportSecurityConfig {
                require_tls_proxy: true,
                trusted_proxies: Vec::new(),
                ..crate::config::TransportSecurityConfig::default()
            },
        );
        for path in [CANONICAL, LEGACY] {
            assert_eq!(request(&transport_state, Method::GET, path).await?.status(), StatusCode::FORBIDDEN);
        }
        // Make the loaded configuration revision stale before either request.
        sqlx::query(r#"UPDATE aegaeon.configuration_versions SET configuration_document = jsonb_set(configuration_document, '{scopeAllowlist}', '["openid","read"]') WHERE environment_id = $1 AND status = 'ACTIVE'"#)
            .bind(env.environment_id).execute(&pool).await?;
        for path in [CANONICAL, LEGACY] {
            assert_eq!(request(&state, Method::GET, path).await?.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
