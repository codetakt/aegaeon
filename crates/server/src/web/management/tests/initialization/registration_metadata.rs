use super::*;
use crate::web::test_support::{sample_registered_client, TestEnvironment};
use serde_json::{json, Value};

async fn saved(pool: &PgPool, environment: Uuid) -> crate::web::test_support::TestResult<Value> {
    let mut values = Vec::new();
    for table in [
        "clients",
        "client_secrets",
        "dynamic_client_registrations",
        "audit_events",
    ] {
        values.push(sqlx::query_scalar::<_,Value>(&format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM aegaeon.{table} t WHERE environment_id=$1")).bind(environment).fetch_one(pool).await?);
    }
    Ok(json!(values))
}

async fn login(
    pool: &PgPool,
    env: &TestEnvironment,
) -> crate::web::test_support::TestResult<(Router, String)> {
    let mut management = test_management_state();
    management.cfg = std::sync::Arc::new(
        super::super::super::ManagementConfig::try_from_env_with_database(pool).await?,
    );
    let mut state = crate::web::test_support::test_app_state(pool.clone(), env).await?;
    state.management = management;
    let app = crate::web::build_router(state);
    let response = app
        .clone()
        .oneshot(request(
            "/api/v1/authentication/sessions",
            json!({"email":input().owner_email,"password":input().owner_password}),
            "",
            "https://admin.aegaeon.test",
            true,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("aegaeon_admin_session="))
        .ok_or("cookie")?
        .split(';')
        .next()
        .ok_or("cookie")?
        .to_owned();
    Ok((app, cookie))
}

async fn patch(
    app: &Router,
    cookie: &str,
    uri: &str,
    payload: Value,
) -> crate::web::test_support::TestResult<(StatusCode, Value)> {
    let mut req = request(uri, payload, cookie, "https://admin.aegaeon.test", true);
    *req.method_mut() = Method::PATCH;
    let response = app.clone().oneshot(req).await?;
    let status = response.status();
    let value = serde_json::from_slice(&body::to_bytes(response.into_body(), 65536).await?)?;
    Ok((status, value))
}

async fn scenario(pool: &PgPool) -> ManagementTestResult {
    let init = initialize_management(pool, &input()).await?;
    let env = TestEnvironment {
        team_id: init.team_id,
        tenant_id: init.tenant_id,
        environment_id: init.environment_id,
        issuer_url: format!("https://{}", init.issuer_host),
        issuer_host: init.issuer_host,
    };
    sqlx::query("INSERT INTO aegaeon.oauth_profiles (environment_id,configuration_version_id,name,profile_type,is_default,allowed_grant_types,token_endpoint_auth_methods_allowed) VALUES ($1,$2,'metadata-test','DOWNSTREAM',true,ARRAY['authorization_code','client_credentials'],ARRAY['client_secret_basic','none'])").bind(env.environment_id).bind(init.configuration_version_id).execute(pool).await?;
    let mut client = sample_registered_client("management-metadata");
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.client_secret = Some("fixture-secret".into());
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        "management-metadata-rat",
        "seed",
    )
    .await?;
    let stored = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        &client.client_id,
        "management-metadata-rat",
    )
    .await?
    .ok_or("stored")?;
    let (app, cookie) = login(pool, &env).await?;
    let uri = format!(
        "/api/v1/teams/{}/environments/{}/clients/{}",
        env.team_id, env.environment_id, stored.database_client_id
    );
    let payload = json!({"baseConfigurationVersionId":init.configuration_version_id,"allowedGrantTypes":["client_credentials"],"redirectUris":[]});
    let before = saved(pool, env.environment_id).await?;
    let mut stale = payload.clone();
    stale["baseConfigurationVersionId"] = json!(Uuid::new_v4());
    assert_eq!(
        patch(&app, &cookie, &uri, stale).await?.0,
        StatusCode::CONFLICT
    );
    assert_eq!(before, saved(pool, env.environment_id).await?);
    sqlx::query("UPDATE aegaeon.team_memberships SET role='READONLY' WHERE team_id=$1")
        .bind(env.team_id)
        .execute(pool)
        .await?;
    assert_eq!(
        patch(&app, &cookie, &uri, payload.clone()).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(before, saved(pool, env.environment_id).await?);
    sqlx::query("UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1")
        .bind(env.team_id)
        .execute(pool)
        .await?;
    // Force an actual post-update audit failure to establish transaction rollback.
    sqlx::raw_sql("CREATE FUNCTION aegaeon.metadata_test_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$; CREATE TRIGGER metadata_test_audit_fail BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.metadata_test_audit_fail()").execute(pool).await?;
    let (status, value) = patch(&app, &cookie, &uri, payload.clone()).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{value}");
    assert_eq!(value["errorCode"], "audit_failure");
    assert_eq!(before, saved(pool, env.environment_id).await?);
    sqlx::raw_sql("DROP TRIGGER metadata_test_audit_fail ON aegaeon.audit_events; DROP FUNCTION aegaeon.metadata_test_audit_fail()").execute(pool).await?;
    let (status, value) = patch(&app, &cookie, &uri, payload).await?;
    assert_eq!(status, StatusCode::OK, "{value}");
    let loaded = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        &client.client_id,
        "management-metadata-rat",
    )
    .await?
    .ok_or("same RAT remains valid")?;
    assert!(loaded.response_types.is_empty());
    assert_eq!(
        loaded.client.allowed_grant_types,
        vec!["client_credentials"]
    );
    let after = saved(pool, env.environment_id).await?;
    assert_eq!(
        before[1], after[1],
        "management metadata update preserves every credential row"
    );
    assert_eq!(
        before[2][0]["registration_access_token_hash"],
        after[2][0]["registration_access_token_hash"]
    );
    assert_ne!(before[3], after[3], "successful mutation audited");
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual management HTTP and transactional rollback"]
async fn pg_registration_metadata_management_sync_preserves_credentials_and_authority_checks(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = scenario(&pool).await;
    finish(result, cleanup(control, pool, &name).await)
}

mod dpop_minimum;
