//! Actual router/method regressions; the DPoP test double checks claims, not signatures.
use super::sender_contract;
use crate::application_authorization::{store::capture, Authority};
use crate::authcode::types::{AccessToken, BearerTokenMeta, BearerTokenMetaInput};
use crate::metrics_integration::MetricsIntegration;
use crate::web::test_support::{
    cleanup_test_environment, finish_test, seed_test_projection, setup_test_environment,
    test_app_state, test_pg_pool, TestEnvironment, TestResult,
};
use crate::web::AppState;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
    response::Response,
    Extension,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

async fn fixture(pool: &PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    seed_test_projection(
        pool,
        env,
        "client",
        "user",
        json!([format!("{}/userinfo", env.issuer_url)]),
        json!({"roles":["USER"],"organization_roles":[]}),
    )
    .await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    state.application_authority = Some(Authority {
        projections: pool.clone(),
        memberships: None,
    });
    state.tokens.validator = Arc::new(crate::authcode::TokenValidator::with_policy(
        state.tokens.store.as_ref().clone(),
        Arc::clone(&state.keys.access_token),
        crate::policy::SecurityPolicy::default()
            .with_sender_constraint(crate::policy::SenderConstraint::None),
    ));
    state.oidc.userinfo_endpoint = Some(Arc::new(crate::oidc::userinfo::UserinfoEndpoint::new(
        state.tokens.validator.as_ref().clone(),
        pool.clone(),
        env.issuer_url.clone(),
    )));
    Ok(state)
}

async fn token(state: &AppState, audience_path: &str, bound: bool) -> TestResult<String> {
    if bound {
        return sender_contract::install_token(state, audience_path, "openid read").await;
    }
    let access = AccessToken::new(
        "client".into(),
        "user".into(),
        Some("openid read".into()),
        60,
    );
    let token = access.token.clone();
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        granted_scopes: vec!["openid".into(), "read".into()],
        audience: format!("{}{audience_path}", state.issuer),
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access.created_at + Duration::from_secs(60),
        refresh_parent: None,
    });
    state
        .tokens
        .store
        .store_issued_grant_async(access, None, meta)
        .await?;
    Ok(token)
}

async fn request(
    state: &AppState,
    path: &str,
    method: Method,
    token: &str,
    proof_method: Option<&str>,
) -> TestResult<Response> {
    let scheme = if proof_method.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("{scheme} {token}"));
    if let Some(proof_method) = proof_method {
        request = request.header("dpop", sender_contract::proof(proof_method, path, token)?);
    }
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        "127.0.0.1:12345".parse::<std::net::SocketAddr>()?,
    )));
    Ok(app.oneshot(request.body(Body::empty())?).await?)
}

fn latency_counts() -> TestResult<(u64, u64)> {
    MetricsIntegration::with_global(|integration| {
        let histogram = &integration.metrics.request_latency;
        (
            histogram
                .with_label_values(&["/resource", "GET"])
                .get_sample_count(),
            histogram
                .with_label_values(&["/resource", "HEAD"])
                .get_sample_count(),
        )
    })
    .ok_or_else(|| "global metrics missing".into())
}

async fn check_response(
    response: Response,
    path: &str,
    method: &Method,
    accepted: bool,
) -> TestResult {
    assert_eq!(
        response.status(),
        if accepted {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        }
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    if !accepted {
        assert_eq!(
            response.headers()["www-authenticate"],
            "DPoP realm=\"aegaeon\", error=\"invalid_dpop_proof\""
        );
    }
    let body = to_bytes(response.into_body(), 65536).await?;
    if method == Method::HEAD {
        assert!(body.is_empty(), "HEAD response must not contain a body");
    } else {
        let body: Value = serde_json::from_slice(&body)?;
        if !accepted {
            assert_eq!(body["error"], "invalid_dpop_proof");
        } else if path == "/resource" {
            assert_eq!(body["status"], "granted");
        } else {
            assert_eq!(body["sub"], "user");
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and serial metrics observations"]
async fn pg_dpop_router_matches_actual_get_and_head_methods() -> TestResult {
    let integration = Arc::new(MetricsIntegration::new(Arc::new(
        aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?,
    )));
    MetricsIntegration::register_global(&integration);
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        for path in ["/userinfo", "/resource", "/application/authorization"] {
            let audience_path = if path == "/application/authorization" {
                "/userinfo"
            } else {
                path
            };
            for bound in [true, false] {
                let token = token(&state, audience_path, bound).await?;
                if path == "/application/authorization" {
                    let mut meta = state
                        .tokens
                        .store
                        .try_get_bearer_meta(&token)?
                        .ok_or("metadata")?;
                    meta.application_grant =
                        capture(&pool, env.environment_id, &env.issuer_url, "client", "user")
                            .await?;
                    assert!(meta.application_grant.is_some());
                    state.tokens.store.try_replace_bearer_meta_record(meta)?;
                }
                for (method, claimed_method, matches) in [
                    (Method::GET, "GET", true),
                    (Method::HEAD, "HEAD", true),
                    (Method::GET, "HEAD", false),
                    (Method::HEAD, "GET", false),
                ] {
                    if !bound && !matches {
                        continue;
                    }
                    let before = latency_counts()?;
                    let response = request(
                        &state,
                        path,
                        method.clone(),
                        &token,
                        bound.then_some(claimed_method),
                    )
                    .await?;
                    check_response(response, path, &method, matches).await?;
                    if path == "/resource" && matches {
                        let expected = if method == Method::HEAD {
                            (before.0, before.1 + 1)
                        } else {
                            (before.0 + 1, before.1)
                        };
                        assert_eq!(latency_counts()?, expected);
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
