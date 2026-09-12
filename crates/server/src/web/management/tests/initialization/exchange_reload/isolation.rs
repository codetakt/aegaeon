use super::*;

async fn environment_rows(
    pool: &PgPool,
    environment: Uuid,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut rows = serde_json::Map::new();
    for table in [
        "clients",
        "oauth_profiles",
        "connections",
        "runtime_keys",
        "client_secrets",
        "configuration_versions",
        "environment_policies",
    ] {
        let value: Value = sqlx::query_scalar(&format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text), '[]'::jsonb) FROM aegaeon.{table} t WHERE environment_id=$1"
        )).bind(environment).fetch_one(pool).await?;
        rows.insert(table.into(), value);
    }
    Ok(Value::Object(rows))
}

pub(super) async fn change_other_environment(
    app: &Router,
    pool: &PgPool,
    env: &TestEnvironment,
    session: &str,
    original: &crate::web::AppState,
    source: &str,
    redis: bool,
) -> ManagementTestResult {
    let before = environment_rows(pool, env.environment_id).await?;
    let uri = format!(
        "/api/v1/teams/{}/tenants/{}/environments",
        env.team_id, env.tenant_id
    );
    let response = app
        .clone()
        .oneshot(request(
            &uri,
            json!({"name":"Other", "slug":"other"}),
            session,
            "https://admin.aegaeon.test",
            true,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&body::to_bytes(response.into_body(), 65536).await?)?;
    let host = body["issuerHost"]
        .as_str()
        .ok_or("other issuer")?
        .to_owned();
    let other = TestEnvironment {
        team_id: env.team_id,
        tenant_id: env.tenant_id,
        environment_id: Uuid::parse_str(body["id"].as_str().ok_or("other environment")?)?,
        issuer_url: format!("https://{host}"),
        issuer_host: host,
    };
    let loaded =
        crate::runtime_configuration::load_database_runtime_configuration(pool, &other.issuer_host)
            .await?;
    sqlx::query("INSERT INTO aegaeon.oauth_profiles (environment_id,configuration_version_id,name,profile_type,is_default,require_pkce,sender_constrained,allowed_grant_types,token_endpoint_auth_methods_allowed) VALUES ($1,$2,'exchange-fixture','DOWNSTREAM',true,true,'NONE',ARRAY['authorization_code'],ARRAY['none'])")
        .bind(other.environment_id).bind(loaded.active_configuration_version_id).execute(pool).await?;
    patch(app, pool, &other, session, json!({"tokenExchange":exchange::policy(&other.issuer_url)?,
        "senderConstraint":"none", "jwtAccessTokensEnabled":true, "retainRefreshChain":true,
        "allowedGrantTypes":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:token-exchange"]})).await?;
    let mut seeded = exchange::fixture(pool, &other).await?;
    if redis {
        exchange::use_redis(&mut seeded)?;
    }
    let after = reload(pool, &other, &seeded).await?;
    let foreign = exchange::grant(&after).await?;
    let foreign = foreign["access_token"].as_str().ok_or("foreign source")?;
    for (state, token) in [(&after, source), (original, foreign)] {
        let (status, body) =
            exchange::exchange(state, token, &[("audience", "internal-api")], true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "foreign source: {body}");
        assert!(body.get("access_token").is_none());
    }
    let (status, body) =
        exchange::exchange(&after, foreign, &[("audience", "internal-api")], true).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "other environment's own grant: {body}"
    );
    assert_eq!(environment_rows(pool, env.environment_id).await?, before);
    Ok(())
}
