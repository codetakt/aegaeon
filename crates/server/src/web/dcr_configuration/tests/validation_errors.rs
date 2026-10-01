mod cases;
use super::*;
use crate::management::types::PolicyDocument;

fn metadata() -> Value {
    json!({"redirect_uris":["https://client.example/callback"],
        "token_endpoint_auth_method":"client_secret_basic", "grant_types":["authorization_code"],
        "scope":"openid"})
}

fn request(
    method: Method,
    path: &str,
    token: Option<&str>,
    value: &Value,
) -> TestResult<Request<Body>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    Ok(request.body(Body::from(serde_json::to_vec(value)?))?)
}

async fn error_response(response: Response, status: StatusCode, error: &str) -> TestResult {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    let body = response_json(response).await?;
    assert_eq!(body["error"], error);
    let description = body["error_description"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing error description"))?;
    assert!(description
        .bytes()
        .all(|c| matches!(c, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e)));
    assert!(!description.contains("https://client.example"));
    assert!(!description.contains("private-sentinel"));
    Ok(())
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

async fn create(app: &axum::Router, value: &Value) -> TestResult<(String, String)> {
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/register", None, value)?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response_json(response).await?;
    let field = |name| {
        body[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other("registration response field missing"))
    };
    assert!(!field("client_secret")?.is_empty());
    Ok((field("client_id")?, field("registration_access_token")?))
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; missing configuration is an error"]
async fn dcr_validation_categories_preserve_rows_and_owner_tokens() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or_else(|| io::Error::other("AEGAEON_DATABASE_URL required"))?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=ARRAY['client_secret_basic','none'] WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    let state = test_app_state(pool.clone(), env).await?;
    let open = crate::web::router::build_router(state.clone());
    let (client, token) = create(&open, &metadata()).await?;
    let active_secrets = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM aegaeon.client_secrets WHERE environment_id=$1 AND status='ACTIVE'",
    )
    .bind(env.environment_id)
    .fetch_one(pool)
    .await?;
    assert_eq!(active_secrets, 1);
    let mut cases = cases::plain();
    for statement in ["private-sentinel", ""] {
        let mut value = metadata();
        value["software_statement"] = json!(statement);
        cases.push(("unapproved_software_statement", value));
    }
    check_rejections(pool, env, &open, &client, &token, cases).await?;
    let mut state = state;
    let policy = PolicyDocument {
        ssa_jwt_pem: Some(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/rsa2048-public.pem"
            ))
            .into(),
        ),
        ssa_expected_iss: Some("https://ssa.example".into()),
        ..PolicyDocument::default()
    };
    state.dcr_validation_config = crate::dcr::DcrValidationConfig::try_from_policy(
        &policy, false, false, false, false, 8192,
    )?;
    let app = crate::web::router::build_router(state);
    let good = cases::with_statement(cases::claims())?;
    create(&app, &good).await?;
    check_rejections(pool, env, &app, &client, &token, cases::statements()?).await?;
    successful_update(&app, &client, &token, good).await?;
    // A missing default profile is server state, not invalid submitted metadata.
    sqlx::query("DELETE FROM aegaeon.oauth_profiles WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    let before = state_digest(pool, env).await?;
    let response = app
        .oneshot(request(Method::POST, "/register", None, &metadata())?)
        .await?;
    error_response(response, StatusCode::INTERNAL_SERVER_ERROR, "server_error").await?;
    assert_eq!(before, state_digest(pool, env).await?);
    Ok(())
}

async fn check_rejections(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    app: &axum::Router,
    client: &str,
    token: &str,
    cases: Vec<(&str, Value)>,
) -> TestResult {
    for (error, value) in cases {
        for method in [Method::POST, Method::PUT] {
            let before = state_digest(pool, env).await?;
            let mut value = value.clone();
            let (path, token) = if method == Method::PUT {
                value["client_id"] = json!(client);
                (format!("/register/{client}"), Some(token))
            } else {
                ("/register".into(), None)
            };
            let response = app
                .clone()
                .oneshot(request(method, &path, token, &value)?)
                .await?;
            error_response(response, StatusCode::BAD_REQUEST, error).await?;
            assert_eq!(before, state_digest(pool, env).await?);
        }
        let response = app
            .clone()
            .oneshot(registration_request(
                Method::GET,
                client,
                Some(token),
                None,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
    }
    Ok(())
}

async fn successful_update(
    app: &axum::Router,
    client: &str,
    token: &str,
    mut value: Value,
) -> TestResult {
    value["client_id"] = json!(client);
    let response = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/register/{client}"),
            Some(token),
            &value,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let updated = response_json(response).await?;
    assert_eq!(updated["client_id"], client);
    let replacement = updated["registration_access_token"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing token"))?;
    assert!(replacement != token, "owner token was not rotated");
    let read = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            client,
            Some(replacement),
            None,
        )?)
        .await?;
    assert_eq!(read.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn dcr_database_failures_remain_server_errors() -> TestResult {
    let response = crate::web::dcr_runtime::dcr_database_error_response(
        &crate::dcr_persistence::DcrDatabaseError::Database(sqlx::Error::PoolClosed),
        "https://issuer.example",
    );
    error_response(response, StatusCode::INTERNAL_SERVER_ERROR, "server_error").await
}
