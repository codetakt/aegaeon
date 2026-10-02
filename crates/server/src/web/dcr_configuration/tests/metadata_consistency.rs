use super::*;
use crate::dcr_persistence::test_database::Database;
use crate::policy::DEVICE_CODE_GRANT_TYPE;
use crate::web::test_support::update_test_policy;
mod credential_admission;
mod credential_races;
mod lifecycle;
mod preparation_currentness;
mod refusals;

async fn router(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult<axum::Router> {
    let grants = vec![
        "authorization_code".to_string(),
        "refresh_token".into(),
        "client_credentials".into(),
        DEVICE_CODE_GRANT_TYPE.into(),
    ];
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1, token_endpoint_auth_methods_allowed=ARRAY['none','client_secret_basic','client_secret_post','private_key_jwt'] WHERE environment_id=$2")
        .bind(&grants).bind(env.environment_id).execute(pool).await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    let policy = crate::management::types::PolicyDocument {
        dcr_enabled: true,
        dcr_everparse_runtime_enabled: true,
        allowed_grant_types: grants,
        ..Default::default()
    };
    update_test_policy(&mut state, |p| *p = policy.clone()).await?;
    state.dcr_validation_config = crate::dcr::DcrValidationConfig::try_from_policy(
        &policy,
        false,
        false,
        true,
        true,
        state.cfg.jose_header_max_len,
    )?;
    Ok(crate::web::router::build_router(state))
}

fn request(
    method: Method,
    path: &str,
    token: Option<&str>,
    value: &Value,
) -> TestResult<Request<Body>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    Ok(builder.body(Body::from(serde_json::to_vec(value)?))?)
}

fn field<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    value[name]
        .as_str()
        .ok_or_else(|| io::Error::other(format!("missing {name}")).into())
}

async fn read(app: &axum::Router, value: &Value) -> TestResult<Value> {
    let response = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            field(value, "client_id")?,
            Some(field(value, "registration_access_token")?),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

async fn digest(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult<String> {
    let mut values = Vec::new();
    for table in [
        "clients",
        "client_secrets",
        "dynamic_client_registrations",
        "audit_events",
    ] {
        values.push(sqlx::query_scalar::<_,Value>(&format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM aegaeon.{table} t WHERE environment_id=$1"))
            .bind(env.environment_id).fetch_one(pool).await?);
    }
    Ok(aegaeon_crypto::hash::sha256_hex(&serde_json::to_vec(
        &values,
    )?))
}

async fn post(app: &axum::Router, metadata: &Value) -> TestResult<Value> {
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/register", None, metadata)?)
        .await?;
    let status = response.status();
    let value = response_json(response).await?;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    Ok(value)
}
