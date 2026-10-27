//! Exercises the production router; the test DPoP verifier checks claims, not signatures.
use super::{error, sender_contract};
use crate::authcode::types::{AccessToken, BearerTokenMeta, BearerTokenMetaInput};
use crate::web::test_support::{
    cleanup_test_environment, finish_test, setup_test_environment, test_app_state, test_pg_pool,
    TestResult,
};
use crate::web::AppState;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    response::Response,
    Extension,
};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

async fn post(state: &AppState, headers: HeaderMap, body: String) -> TestResult<Response> {
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        "127.0.0.1:12345".parse::<std::net::SocketAddr>()?,
    )));
    let mut request = Request::post("/userinfo").body(Body::from(body))?;
    *request.headers_mut() = headers;
    Ok(app.oneshot(request).await?)
}

async fn bearer_token(state: &AppState) -> TestResult<String> {
    let access = AccessToken::new("client".into(), "user".into(), Some("openid".into()), 60);
    let token = access.token.clone();
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        granted_scopes: vec!["openid".into()],
        audience: format!("{}/userinfo", state.issuer),
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

async fn success(response: Response) -> TestResult {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let claims: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(claims["sub"], "user");
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn userinfo_post_router_accepts_header_and_form_bearer_presentations() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = test_app_state(pool.clone(), &env).await?;
        state.tokens.validator = Arc::new(crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            Arc::clone(&state.keys.access_token),
            crate::policy::SecurityPolicy::default()
                .with_sender_constraint(crate::policy::SenderConstraint::None),
        ));
        state.oidc.userinfo_endpoint =
            Some(Arc::new(crate::oidc::userinfo::UserinfoEndpoint::new(
                state.tokens.validator.as_ref().clone(),
                pool.clone(),
                env.issuer_url.clone(),
            )));
        let token = bearer_token(&state).await?;
        for (content_type, body, header) in [
            (None, String::new(), true),
            (
                Some("application/x-www-form-urlencoded"),
                String::new(),
                true,
            ),
            (
                Some("application/x-www-form-urlencoded"),
                "unused=value".into(),
                true,
            ),
            (
                Some("application/x-www-form-urlencoded"),
                format!("access_token={token}"),
                false,
            ),
        ] {
            let mut headers = HeaderMap::new();
            if let Some(content_type) = content_type {
                headers.insert("content-type", content_type.parse()?);
            }
            if header {
                headers.insert("authorization", format!("Bearer {token}").parse()?);
            }
            success(post(&state, headers, body).await?).await?;
        }
        for (content_type, body, authorization, status, code) in [
            (
                Some("application/x-www-form-urlencoded"),
                format!("access_token={token}"),
                true,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                Some("application/x-www-form-urlencoded"),
                format!("access_token={token}&access_token={token}"),
                false,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                Some("application/json"),
                format!("access_token={token}"),
                true,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                Some("; charset=utf-8"),
                format!("access_token={token}"),
                true,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                None,
                format!("access_token={token}"),
                true,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                None,
                String::new(),
                false,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
            ),
            (
                Some("application/x-www-form-urlencoded"),
                "x".repeat(2 * 1024 * 1024 + 1),
                true,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
        ] {
            let mut headers = HeaderMap::new();
            if let Some(content_type) = content_type {
                headers.insert("content-type", content_type.parse()?);
            }
            if authorization {
                headers.insert("authorization", format!("Bearer {token}").parse()?);
            }
            error(post(&state, headers, body).await?, status, code).await?;
        }
        let mut headers = HeaderMap::new();
        headers.append("authorization", format!("Bearer {token}").parse()?);
        headers.append("authorization", format!("Bearer {token}").parse()?);
        error(
            post(&state, headers, String::new()).await?,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn userinfo_post_router_checks_dpop_method_hash_and_presentation() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = test_app_state(pool.clone(), &env).await?;
        state.tokens.validator = Arc::new(crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            Arc::clone(&state.keys.access_token),
            crate::policy::SecurityPolicy::default()
                .with_sender_constraint(crate::policy::SenderConstraint::None),
        ));
        state.oidc.userinfo_endpoint =
            Some(Arc::new(crate::oidc::userinfo::UserinfoEndpoint::new(
                state.tokens.validator.as_ref().clone(),
                pool.clone(),
                env.issuer_url.clone(),
            )));
        let token = sender_contract::install_token(&state, "/userinfo", "openid").await?;
        for (method, hash_token, scheme, expected) in [
            ("POST", token.as_str(), "DPoP", None),
            ("GET", token.as_str(), "DPoP", Some("invalid_dpop_proof")),
            ("POST", "wrong-token", "DPoP", Some("invalid_dpop_proof")),
            ("POST", token.as_str(), "Bearer", Some("invalid_token")),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("authorization", format!("{scheme} {token}").parse()?);
            headers.insert(
                "dpop",
                sender_contract::proof(method, "/userinfo", hash_token)?.parse()?,
            );
            let response = post(&state, headers, String::new()).await?;
            if let Some(code) = expected {
                error(response, StatusCode::UNAUTHORIZED, code).await?;
            } else {
                success(response).await?;
            }
        }
        // A body access_token is a Bearer presentation even if a proof accompanies it.
        for include_proof in [false, true] {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "application/x-www-form-urlencoded".parse()?);
            if include_proof {
                headers.insert(
                    "dpop",
                    sender_contract::proof("POST", "/userinfo", &token)?.parse()?,
                );
            }
            error(
                post(&state, headers, format!("access_token={token}")).await?,
                StatusCode::UNAUTHORIZED,
                if include_proof {
                    "invalid_dpop_proof"
                } else {
                    "invalid_token"
                },
            )
            .await?;
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
