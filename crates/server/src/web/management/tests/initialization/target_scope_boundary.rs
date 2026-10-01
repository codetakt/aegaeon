use super::*;
use crate::web::test_support::TestResult as DataResult;
use serde_json::{json, Value};

const CALLER: &str = "scope-caller";

async fn send(
    app: &Router,
    session: &str,
    uri: &str,
    method: Method,
    payload: Value,
) -> DataResult<(StatusCode, Value)> {
    let mut req = request(uri, payload, session, "https://admin.aegaeon.test", true);
    *req.method_mut() = method;
    let response = app.clone().oneshot(req).await?;
    let status = response.status();
    Ok((
        status,
        serde_json::from_slice(&body::to_bytes(response.into_body(), 1024 * 1024).await?)?,
    ))
}

fn policies() -> Value {
    json!({"tokenExchange":{"version":1,"targets":[{
        "audience":"https://api.example/resource","resourceAliases":["https://api.example/resource"]}],
        "rules":[{"clientId":CALLER,"sourceAudience":"source-api",
        "targetAudience":"https://api.example/resource","scopes":[
            {"targetScope":"profile","sourceScopes":["profile"]},
            {"targetScope":"email","sourceScopes":["profile"]}],"defaultScopes":["profile"]}]},
        "clientCredentials":{"version":1,"resourceServers":[{
            "targetAudience":"https://api.example/resource","introspectionClients":[]}],
        "rules":[{"clientId":CALLER,"targetAudience":"https://api.example/resource",
            "scopes":["profile","email"],"defaultScopes":["profile"],"defaultTarget":true}]},
        "allowSecurityDowngrade":true,"reason":"scope ceiling regression"})
}

async fn active(pool: &PgPool, environment: Uuid) -> DataResult<Uuid> {
    Ok(sqlx::query_scalar(
        "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1",
    )
    .bind(environment)
    .fetch_one(pool)
    .await?)
}

async fn saved(pool: &PgPool, environment: Uuid) -> DataResult<Vec<Value>> {
    let mut result = vec![];
    for table in [
        "configuration_versions",
        "environment_policies",
        "clients",
        "client_secrets",
        "dynamic_client_registrations",
        "audit_events",
    ] {
        let rows: Vec<Value> = sqlx::query_scalar(&format!(
            "SELECT to_jsonb(t) FROM aegaeon.{table} t WHERE environment_id=$1 ORDER BY to_jsonb(t)::text"))
            .bind(environment).fetch_all(pool).await?;
        result.push(json!(rows));
    }
    result.push(json!(active(pool, environment).await?.to_string()));
    Ok(result)
}

fn assert_scope_error(status: StatusCode, value: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert_eq!(value["errorCode"], "invalid_request", "{value}");
    let violations = value["details"]["scopeViolations"]
        .as_array()
        .expect("all violations");
    assert_eq!(violations.len(), 2, "{value}");
    assert_eq!(violations[0]["rule"], "tokenExchange.rules[0]");
    assert_eq!(violations[1]["rule"], "clientCredentials.rules[0]");
    for violation in violations {
        assert_eq!(violation["clientId"], CALLER);
        assert_eq!(violation["scope"], "email");
    }
    assert!(value["message"].as_str().unwrap().contains(CALLER));
}

async fn seed_caller(
    pool: &PgPool,
    host: &str,
    environment: Uuid,
    version: Uuid,
) -> DataResult<crate::dcr_persistence::DcrStoredClient> {
    sqlx::query("INSERT INTO aegaeon.oauth_profiles (environment_id, configuration_version_id, name, profile_type, is_default, allowed_grant_types, token_endpoint_auth_methods_allowed) VALUES ($1,$2,'scope-fixture','DOWNSTREAM',true,ARRAY['authorization_code'],ARRAY['none'])")
        .bind(environment).bind(version).execute(pool).await?;
    let mut client = crate::web::test_support::sample_registered_client(CALLER);
    client.allowed_scopes = vec!["profile".into()];
    client.allowed_grant_types = vec!["authorization_code".into()];
    client.client_secret = None;
    client.token_endpoint_auth_method = "none".into();
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        host,
        &client,
        &["code".into()],
        "scope-registration-token",
        "scope-create",
    )
    .await?;
    Ok(crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        host,
        CALLER,
        "scope-registration-token",
    )
    .await?
    .ok_or("stored client")?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_target_scope_boundary_checks_policy_client_dcr_and_drafts() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = async {
        let init = initialize_management(&pool, &input()).await?;
        let stored = seed_caller(&pool, &init.issuer_host, init.environment_id, init.configuration_version_id).await?;
        let (app, session) = super::client_credentials_policy::management_session(&pool).await?;
        let root = format!("/api/v1/teams/{}/environments/{}", init.team_id, init.environment_id);
        let mut policy = policies();
        policy["baseConfigurationVersionId"] = json!(init.configuration_version_id);
        let before = saved(&pool, init.environment_id).await?;
        let (status, value) = send(&app, &session, &format!("{root}/policies"), Method::PATCH, policy.clone()).await?;
        assert_scope_error(status, &value);
        assert_eq!(saved(&pool, init.environment_id).await?, before);

        let document: Value = sqlx::query_scalar("SELECT configuration_document FROM aegaeon.configuration_versions WHERE id=$1")
            .bind(init.configuration_version_id).fetch_one(&pool).await?;
        let mut candidate = document;
        candidate["policy"]["tokenExchange"] = policy["tokenExchange"].clone();
        candidate["policy"]["clientCredentials"] = policy["clientCredentials"].clone();
        let draft = json!({"baseConfigurationVersionId":init.configuration_version_id,"configurationDocument":candidate});
        let (status, value) = send(&app, &session, &format!("{root}/configurationVersions"), Method::POST, draft.clone()).await?;
        assert_scope_error(status, &value);
        assert_eq!(saved(&pool, init.environment_id).await?, before);

        let mut expanded = stored.client.clone();
        expanded.allowed_scopes.push("email".into());
        crate::dcr_persistence::update_dynamic_registration(&pool, &stored, &expanded,
            &["code".into()], "scope-registration-token", crate::dcr_persistence::DcrClientSecretChange::Preserve,
            "scope-expand").await?;
        let (status, draft_value) = send(&app, &session, &format!("{root}/configurationVersions"), Method::POST, draft).await?;
        assert_eq!(status, StatusCode::CREATED, "{draft_value}");
        let draft_id = draft_value["id"].as_str().ok_or("draft id")?;
        let (status, value) = send(&app, &session, &format!("{root}/policies"), Method::PATCH, policy).await?;
        assert_eq!(status, StatusCode::OK, "{value}");
        let version = active(&pool, init.environment_id).await?;
        check_client_writes(&pool, &app, &session, &root, &init.issuer_host, init.environment_id).await?;

        // Draft creation is not a reservation. Remove the live rules and shrink
        // through the API, then activation must revalidate the previously valid draft.
        let empty = json!({"baseConfigurationVersionId":version,
            "tokenExchange":{"version":1,"targets":[],"rules":[]},
            "clientCredentials":{"version":1,"resourceServers":[],"rules":[]},
            "allowSecurityDowngrade":true,"reason":"remove rules before scope reduction"});
        let (status, value) = send(&app, &session, &format!("{root}/policies"), Method::PATCH, empty).await?;
        assert_eq!(status, StatusCode::OK, "{value}");
        let version = active(&pool, init.environment_id).await?;
        let env = crate::web::test_support::TestEnvironment {
            team_id: init.team_id, tenant_id: init.tenant_id, environment_id: init.environment_id,
            issuer_url: format!("https://{}",init.issuer_host), issuer_host: init.issuer_host.clone(),
        };
        let (app, session) = reloaded_management_session(&pool, &env).await?;
        let (status, value) = send(&app, &session, &format!("{root}/clients/{}",stored.database_client_id), Method::PATCH,
            json!({"baseConfigurationVersionId":version,"allowedScopes":["profile"]})).await?;
        assert_eq!(status, StatusCode::OK, "{value}");
        let before = saved(&pool, init.environment_id).await?;
        let (status, value) = send(&app, &session, &format!("{root}/configurationVersions/{draft_id}/activate"), Method::POST,
            json!({"allowSecurityDowngrade":true,"reason":"activation scope regression"})).await?;
        assert_scope_error(status, &value);
        assert_eq!(saved(&pool, init.environment_id).await?, before);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

async fn check_client_writes(
    pool: &PgPool,
    app: &Router,
    session: &str,
    root: &str,
    host: &str,
    environment: Uuid,
) -> ManagementTestResult {
    let version = active(pool, environment).await?;
    let client_id: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2 AND status='ACTIVE'")
        .bind(environment).bind(CALLER).fetch_one(pool).await?;
    let before = saved(pool, environment).await?;
    let (status, value) = send(
        app,
        session,
        &format!("{root}/clients/{client_id}"),
        Method::PATCH,
        json!({"baseConfigurationVersionId":version,"allowedScopes":["profile"]}),
    )
    .await?;
    assert_scope_error(status, &value);
    assert_eq!(saved(pool, environment).await?, before);
    let stored = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        host,
        CALLER,
        "scope-registration-token",
    )
    .await?
    .ok_or("current DCR client")?;
    let mut narrowed = stored.client.clone();
    narrowed.allowed_scopes = vec!["profile".into()];
    let error = crate::dcr_persistence::update_dynamic_registration(
        pool,
        &stored,
        &narrowed,
        &["code".into()],
        "replacement-registration-token",
        crate::dcr_persistence::DcrClientSecretChange::Preserve,
        "scope-shrink",
    )
    .await
    .expect_err("DCR must reject incompatible scopes");
    assert!(
        matches!(
            error,
            crate::dcr_persistence::DcrDatabaseError::ScopePolicy(_)
        ),
        "{error}"
    );
    assert!(error.to_string().contains("email"));
    assert!(error.to_string().contains("clientCredentials.rules[0]"));
    assert_eq!(saved(pool, environment).await?, before);
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_target_scope_boundary_rechecks_after_environment_lock_wait() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = async {
        let init = initialize_management(&pool, &input()).await?;
        let stored = seed_caller(&pool, &init.issuer_host, init.environment_id, init.configuration_version_id).await?;
        let (app, session) = super::client_credentials_policy::management_session(&pool).await?;
        let uri = format!("/api/v1/teams/{}/environments/{}/policies",init.team_id,init.environment_id);
        // This lock owner models a client mutation. It starts with both scopes
        // available, then removes email while the policy HTTP request waits.
        sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=ARRAY['profile','email'] WHERE id=$1")
            .bind(stored.database_client_id).execute(&pool).await?;
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
            .bind(init.environment_id).fetch_one(&mut *tx).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *tx).await?;
        sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=ARRAY['profile'] WHERE id=$1")
            .bind(stored.database_client_id).execute(&mut *tx).await?;
        let mut policy = policies();
        policy["baseConfigurationVersionId"] = json!(init.configuration_version_id);
        let mut req = request(&uri, policy, &session, "https://admin.aegaeon.test", true);
        *req.method_mut() = Method::PATCH;
        let mut task = tokio::spawn(async move { app.oneshot(req).await });
        let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))")
                    .bind(pid).fetch_one(&mut *tx).await?;
                if blocked { return Ok::<_,sqlx::Error>(()); }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await;
        if !matches!(observed, Ok(Ok(()))) {
            task.abort(); let _ = task.await; tx.rollback().await?;
            return Err("policy request did not demonstrably wait on the environment lock".into());
        }
        tx.commit().await?;
        let response = match tokio::time::timeout(std::time::Duration::from_secs(5), &mut task).await {
            Ok(result) => result??,
            Err(_) => { task.abort(); let _ = task.await; return Err("policy request did not finish".into()); }
        };
        let status = response.status();
        let value = serde_json::from_slice(&body::to_bytes(response.into_body(), 1024 * 1024).await?)?;
        assert_scope_error(status, &value);
        assert_eq!(active(&pool,init.environment_id).await?, init.configuration_version_id);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

async fn reloaded_management_session(
    pool: &PgPool,
    env: &crate::web::test_support::TestEnvironment,
) -> DataResult<(Router, String)> {
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
        .ok_or("session cookie")?
        .split(';')
        .next()
        .ok_or("cookie value")?
        .to_owned();
    Ok((app, cookie))
}
