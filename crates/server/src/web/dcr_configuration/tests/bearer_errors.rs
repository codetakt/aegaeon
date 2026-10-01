mod headers;
mod precedence;
mod query;
use super::*;
use crate::web::AppState;
use axum::http::{HeaderMap, HeaderValue};

const INITIAL_TOKEN: &str = "synthetic-initial-registration-token";
const BARE_CHALLENGE: &str = "Bearer realm=\"aegaeon\"";
const REQUEST_CHALLENGE: &str = "Bearer realm=\"aegaeon\", error=\"invalid_request\"";
const TOKEN_CHALLENGE: &str = "Bearer realm=\"aegaeon\", error=\"invalid_token\"";

fn metadata() -> Value {
    json!({"redirect_uris":["https://client.example/callback"],
        "token_endpoint_auth_method":"client_secret_basic", "grant_types":["authorization_code"],
        "scope":"openid"})
}

fn bearer(token: &str) -> TestResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    Ok(headers)
}

fn request(
    method: Method,
    path: &str,
    headers: &HeaderMap,
    body: &str,
) -> TestResult<Request<Body>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))?;
    request.headers_mut().extend(headers.clone());
    Ok(request)
}

async fn state_digest(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult<String> {
    let mut rows = Vec::new();
    for table in [
        "clients",
        "client_secrets",
        "dynamic_client_registrations",
        "audit_events",
    ] {
        let query = format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text), '[]'::jsonb) FROM aegaeon.{table} t WHERE environment_id=$1");
        rows.push(
            sqlx::query_scalar::<_, Value>(&query)
                .bind(env.environment_id)
                .fetch_one(pool)
                .await?,
        );
    }
    Ok(aegaeon_crypto::hash::sha256_hex(&serde_json::to_vec(
        &rows,
    )?))
}

async fn protected_state(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult<AppState> {
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=ARRAY['client_secret_basic','none'] WHERE environment_id=$1")
        .bind(env.environment_id).execute(pool).await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    state.dcr_required_bearer_hash =
        Some(crate::dcr_persistence::dcr_bearer_token_hash(INITIAL_TOKEN));
    Ok(state)
}

async fn create(
    app: &axum::Router,
    headers: &HeaderMap,
    value: &Value,
) -> TestResult<(String, String)> {
    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/register",
            headers,
            &value.to_string(),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response_json(response).await?;
    if value["token_endpoint_auth_method"] == "client_secret_basic" {
        assert!(body["client_secret"]
            .as_str()
            .is_some_and(|secret| !secret.is_empty()));
    }
    let field = |name| {
        body[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other("missing registration field"))
    };
    Ok((field("client_id")?, field("registration_access_token")?))
}

fn response_headers(response: &Response, status: StatusCode, challenge: Option<&str>) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let challenges: Vec<_> = response
        .headers()
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .collect();
    match challenge {
        Some(expected) => {
            assert_eq!(challenges.len(), 1);
            assert_eq!(challenges[0], expected);
        }
        None => assert!(challenges.is_empty()),
    }
}

async fn json_error(response: Response, error: &str, issuer: &str) -> TestResult<Value> {
    let body = response_json(response).await?;
    assert_eq!(body["error"], error);
    assert_eq!(body["iss"], issuer);
    let description = body["error_description"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing error description"))?;
    assert!(description
        .bytes()
        .all(|c| matches!(c, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e)));
    assert!(!description.contains("private-sentinel"));
    Ok(body)
}

async fn empty_body(response: Response) -> TestResult {
    assert!(body::to_bytes(response.into_body(), usize::MAX)
        .await?
        .is_empty());
    Ok(())
}

async fn owner_read(app: &axum::Router, client: &str, token: &str) -> TestResult {
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/register/{client}"),
            &bearer(token)?,
            "",
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await?;
    assert_eq!(body["client_id"], client);
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; missing configuration is an error"]
async fn dcr_bearer_headers_preserve_owner_state_and_token_roles() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or_else(|| io::Error::other("AEGAEON_DATABASE_URL required"))?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = headers::scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; missing configuration is an error"]
async fn dcr_bearer_query_route_and_precedence_contract() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or_else(|| io::Error::other("AEGAEON_DATABASE_URL required"))?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = async {
        let state = protected_state(&pool, &env).await?;
        let app = crate::web::router::build_router(state.clone());
        let (client, token) = create(&app, &bearer(INITIAL_TOKEN)?, &metadata()).await?;
        query::scenario(&pool, &env, &state, &client, &token).await?;
        precedence::scenario(&pool, &env, &state, &client, &token).await
    }
    .await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}
