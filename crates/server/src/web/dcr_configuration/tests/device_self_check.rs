mod lifecycle;
mod refusals;
use super::*;
use crate::web::test_support::update_test_policy;
use crate::{
    dcr::DcrValidationConfig, management::types::PolicyDocument, policy::DEVICE_CODE_GRANT_TYPE,
};

fn metadata() -> Value {
    json!({"redirect_uris":["https://client.example/callback"],
        "token_endpoint_auth_method":"none", "pkce_required":true,
        "grant_types":["authorization_code", DEVICE_CODE_GRANT_TYPE],
        "response_types":["code"], "scope":"openid"})
}

async fn configured_state(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    device: bool,
) -> TestResult<crate::web::AppState> {
    let grants = vec![
        "authorization_code".to_string(),
        DEVICE_CODE_GRANT_TYPE.to_string(),
    ];
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1 WHERE environment_id=$2")
        .bind(&grants)
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    let policy = PolicyDocument {
        dcr_enabled: true,
        dcr_everparse_runtime_enabled: true,
        allowed_grant_types: if device {
            grants
        } else {
            vec!["authorization_code".into()]
        },
        ..PolicyDocument::default()
    };
    update_test_policy(&mut state, |p| *p = policy.clone()).await?;
    let cfg = &state.cfg;
    let runtime = cfg.grant_runtime();
    state.dcr_validation_config = DcrValidationConfig::try_from_policy(
        &policy,
        runtime.jwt_bearer_enabled(),
        runtime.token_exchange_enabled(),
        runtime.device_authorization_enabled(),
        cfg.dcr_everparse_runtime_enabled,
        cfg.jose_header_max_len,
    )?;
    assert!(cfg.dcr_everparse_runtime_enabled);
    assert_eq!(runtime.device_authorization_enabled(), device);
    Ok(state)
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

async fn read(app: &axum::Router, client: &str, token: &str) -> TestResult<Value> {
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
    response_json(response).await
}
