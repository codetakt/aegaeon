//! Shared positive fixtures retain the real restricted-PG namespace validator.
use super::support::{remote, TestResult};
use crate::web::{test_support as t, AppState};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    response::Response,
};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

pub(super) async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    authorization: Option<&str>,
    body: String,
) -> TestResult<Response> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .extension(remote());
    if let Some(value) = content_type {
        request = request.header(header::CONTENT_TYPE, value);
    }
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    Ok(crate::web::build_router(state.clone())
        .oneshot(request.body(Body::from(body))?)
        .await?)
}

pub(super) async fn status(response: Response, expected: StatusCode) -> TestResult<Response> {
    if response.status() != expected {
        let status = response.status();
        let body = to_bytes(response.into_body(), 65536).await?;
        return Err(format!(
            "expected {expected}, received {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    Ok(response)
}

pub(super) async fn json(response: Response, expected: StatusCode) -> TestResult<Value> {
    let status = response.status();
    let value: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(status, expected, "{value}");
    Ok(value)
}

pub(super) fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}

pub(super) async fn bind_policy(mut state: AppState) -> TestResult<AppState> {
    // Use the final state-owned store/key/issuer and DB-derived security policy.
    state.tokens.validator = Arc::new(
        crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            state.keys.access_token.clone(),
            state.cfg.security_policy,
        )
        .with_issuer(Some(state.issuer.to_string()))
        .with_jwt_access_tokens_enabled(state.cfg.enable_jwt_access_tokens),
    );
    state.validate_subject_namespace().await?;
    assert!(state.require_subject_namespace().is_ok());
    Ok(state)
}

pub(super) async fn bearer(
    state: &AppState,
    client: &str,
    subject: &str,
    audience: String,
    scopes: &str,
    grant: Option<crate::application_authorization::inorii::Grant>,
) -> TestResult<String> {
    use crate::authcode::types::{AccessToken, BearerTokenMeta, BearerTokenMetaInput};
    let access = AccessToken::new(client.into(), subject.into(), Some(scopes.into()), 300);
    let token = access.token.clone();
    let mut meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: token.clone(),
        client_id: client.into(),
        user_id: subject.into(),
        granted_scopes: scopes.split_ascii_whitespace().map(str::to_owned).collect(),
        audience,
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access.created_at + Duration::from_secs(300),
        refresh_parent: None,
    });
    meta.application_grant = grant;
    state
        .tokens
        .store
        .store_issued_grant_async(access, None, meta)
        .await?;
    Ok(token)
}

pub(super) async fn pool_environment() -> TestResult<(sqlx::PgPool, t::TestEnvironment)> {
    let pool = t::test_pg_pool()
        .await?
        .ok_or("restricted PostgreSQL required; no silent skip")?;
    let env = t::setup_test_environment(&pool).await?;
    Ok((pool, env))
}
