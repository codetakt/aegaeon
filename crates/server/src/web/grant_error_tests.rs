//! Real token/device routes with PostgreSQL configuration and Redis grant state.
mod codes;
mod devices;
mod policy;
use super::test_support::*;
use super::{AppState, DEVICE_CODE_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;

const OWNER: &str = "grant-owner";
const OTHER: &str = "grant-other";
const LIMITED: &str = "grant-limited";
const SECRET: &str = "synthetic-grant-secret";
const JWT_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "https://client.example.com/callback";
fn client_secret(client: &str) -> &'static str {
    match client {
        OTHER => "synthetic-other-secret",
        LIMITED => "synthetic-limited-secret",
        _ => SECRET,
    }
}
fn grants() -> Vec<String> {
    [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        JWT_GRANT,
        TOKEN_EXCHANGE_GRANT_TYPE,
        DEVICE_CODE_GRANT_TYPE,
    ]
    .map(str::to_string)
    .to_vec()
}
async fn fixture(pool: &PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1, token_endpoint_auth_methods_allowed=$2 WHERE environment_id=$3")
        .bind(grants()).bind(vec!["client_secret_basic"]).bind(env.environment_id).execute(pool).await?;
    for id in [OWNER, OTHER, LIMITED] {
        let mut client = sample_registered_client(id);
        client.client_secret = Some(client_secret(id).into());
        client.token_endpoint_auth_method = "client_secret_basic".into();
        client.allowed_grant_types = if id == LIMITED {
            vec!["authorization_code".into()]
        } else {
            grants()
        };
        crate::dcr_persistence::create_dynamic_registration(
            pool,
            &env.issuer_host,
            &client,
            &["code".into()],
            &format!("synthetic-registration-{id}"),
            "grant-errors",
        )
        .await?;
    }
    let policy = crate::management::types::PolicyDocument {
        allowed_grant_types: grants(),
        sender_constraint: crate::management::types::PolicySenderConstraint::None,
        ..crate::management::types::PolicyDocument::default()
    };
    seed_oidc_configuration(pool, env, policy, "grant-errors").await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(env.environment_id);
    let issuer = crate::authcode::TokenIssuer::try_from_shared_store_env_with_ttls(
        state.keys.access_token.clone(),
        300,
        3600,
        120,
        &namespace,
    )?
    .with_issuer(env.issuer_url.clone());
    state.tokens.store = Arc::new(issuer.token_store.clone());
    state.tokens.issuer = Arc::new(issuer);
    state.device.code_store = Arc::new(
        crate::device_authz::DeviceCodeStore::try_from_shared_store_env_with_policy(
            60, 5, &namespace,
        )?,
    );
    Ok(state)
}
fn form(values: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(values.iter().copied())
        .finish()
}
fn request(path: &str, body: String, client: &str, secret: &str) -> TestResult<Request<Body>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{client}:{secret}"))),
        )
        .body(Body::from(body))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43123))));
    Ok(request)
}
async fn token(state: &AppState, client: &str, values: &[(&str, &str)]) -> TestResult<Response> {
    Ok(super::router::build_router(state.clone())
        .oneshot(request(
            "/token",
            form(values),
            client,
            client_secret(client),
        )?)
        .await?)
}
fn no_cache(response: &Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
}
async fn body(response: Response) -> TestResult<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 65536).await?,
    )?)
}
async fn error(response: Response, status: StatusCode, expected: &str) -> TestResult {
    assert_eq!(response.status(), status);
    no_cache(&response);
    let value = body(response).await?;
    assert_eq!(value["error"], expected);
    for name in [
        "access_token",
        "refresh_token",
        "id_token",
        "client_id",
        "sub",
    ] {
        assert!(value.get(name).is_none());
    }
    assert!(!value.to_string().contains(OWNER));
    assert!(!value.to_string().contains(SECRET));
    Ok(())
}
