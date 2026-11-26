use super::*;
use crate::web::test_support::{seed_oidc_configuration, test_app_state};
use axum::http::header;

const LOGIN: &str = "https://app.example/callback";
const ORIGINAL: &str = "https://app.example/bye";
const REPLACEMENT: &str = "https://app.example/signed-out";

async fn start_logout(
    app: &Router,
    client: &str,
    target: &str,
) -> crate::web::test_support::TestResult<axum::response::Response> {
    let query = serde_urlencoded::to_string([
        ("client_id", client),
        ("post_logout_redirect_uri", target),
        ("state", "inorii"),
    ])?;
    let req = Request::get(format!("/logout?{query}"))
        .extension(ConnectInfo(
            "127.0.0.1:43210".parse::<std::net::SocketAddr>()?,
        ))
        .body(Body::empty())?;
    Ok(app.clone().oneshot(req).await?)
}

async fn confirm_logout(app: &Router, env: &TestEnvironment, client: &str) -> ManagementTestResult {
    let started = start_logout(app, client, REPLACEMENT).await?;
    assert_eq!(started.status(), StatusCode::SEE_OTHER);
    let transaction = started.headers()[header::LOCATION]
        .to_str()?
        .strip_prefix("/logout/confirm?transaction=")
        .ok_or("confirmation redirect")?;
    let cookie = started.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .ok_or("browser cookie")?;
    let location = started.headers()[header::LOCATION].to_str()?;
    let page = Request::get(location)
        .extension(ConnectInfo(
            "127.0.0.1:43210".parse::<std::net::SocketAddr>()?,
        ))
        .header(header::COOKIE, cookie)
        .body(Body::empty())?;
    assert_eq!(app.clone().oneshot(page).await?.status(), StatusCode::OK);
    let form =
        serde_urlencoded::to_string([("transaction", transaction), ("decision", "confirm")])?;
    let req = Request::post("/logout/confirm")
        .extension(ConnectInfo(
            "127.0.0.1:43210".parse::<std::net::SocketAddr>()?,
        ))
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, &env.issuer_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form))?;
    let done = app.clone().oneshot(req).await?;
    assert_eq!(done.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        done.headers()[header::LOCATION].to_str()?,
        format!("{REPLACEMENT}?state=inorii")
    );
    Ok(())
}

async fn check_runtime(
    pool: &PgPool,
    env: &TestEnvironment,
    identifier: &str,
) -> ManagementTestResult {
    let state = test_app_state(pool.clone(), env).await?;
    let app = crate::web::build_router(state);
    confirm_logout(&app, env, identifier).await?;
    for (client, uri) in [
        (identifier, ORIGINAL),
        (identifier, LOGIN),
        ("registered-by-dcr", REPLACEMENT),
    ] {
        assert_eq!(
            start_logout(&app, client, uri).await?.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        start_logout(&app, "registered-by-dcr", ORIGINAL)
            .await?
            .status(),
        StatusCode::SEE_OTHER
    );
    Ok(())
}

async fn registered_environment(
    pool: &PgPool,
) -> crate::web::test_support::TestResult<(TestEnvironment, Uuid)> {
    let init = initialize_management(pool, &input()).await?;
    let env = TestEnvironment {
        team_id: init.team_id,
        tenant_id: init.tenant_id,
        environment_id: init.environment_id,
        issuer_url: format!("https://{}", init.issuer_host),
        issuer_host: init.issuer_host,
    };
    sqlx::query("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,allowed_grant_types,token_endpoint_auth_methods_allowed) VALUES($1,$2,'logout-test','DOWNSTREAM',true,ARRAY['authorization_code'],ARRAY['none'])").bind(env.environment_id).bind(init.configuration_version_id).execute(pool).await?;
    let mut dynamic = sample_registered_client("registered-by-dcr");
    dynamic.post_logout_redirect_uris = vec![ORIGINAL.to_owned()];
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &dynamic,
        &["code".into()],
        "logout-read-token",
        "logout-test",
    )
    .await?;
    let policy = crate::management::types::PolicyDocument {
        oidc_enabled: true,
        oidc_enable_logout: true,
        id_token_time_to_live_seconds: 300,
        ..Default::default()
    };
    seed_oidc_configuration(pool, &env, policy, "logout-test").await?;
    Ok((env, init.configuration_version_id))
}

async fn create_client(
    app: &Router,
    collection: &str,
    cookie: &str,
    payload: Value,
) -> crate::web::test_support::TestResult<Value> {
    let response = app
        .clone()
        .oneshot(request(
            collection,
            payload,
            cookie,
            "https://admin.aegaeon.test",
            true,
        ))
        .await?;
    let status = response.status();
    let bytes = body::to_bytes(response.into_body(), 65536).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let value: Value = serde_json::from_slice(&bytes)?;
    Ok(value)
}

async fn check_registration(pool: &PgPool) -> ManagementTestResult {
    let (env, version) = registered_environment(pool).await?;
    let (app, cookie) = login(pool, &env).await?;
    let collection = format!(
        "/api/v1/teams/{}/environments/{}/clients",
        env.team_id, env.environment_id
    );
    let create = json!({"baseConfigurationVersionId":version,"name":"Public RP","clientType":"PUBLIC","redirectUris":[LOGIN],"postLogoutRedirectUris":[ORIGINAL],"allowedGrantTypes":["authorization_code"],"allowedScopes":[],"tokenEndpointAuthenticationMethod":"none"});
    let mut legacy = create.clone();
    legacy
        .as_object_mut()
        .ok_or("create object")?
        .remove("postLogoutRedirectUris");
    let default = create_client(&app, &collection, &cookie, legacy).await?;
    assert_eq!(default["client"]["postLogoutRedirectUris"], json!([]));
    let value = create_client(&app, &collection, &cookie, create).await?;
    let client = &value["client"];
    assert_eq!(client["postLogoutRedirectUris"], json!([ORIGINAL]));
    let uri = format!("{collection}/{}", client["id"].as_str().ok_or("UUID")?);
    let identifier = client["clientIdentifier"]
        .as_str()
        .ok_or("client identifier")?;
    let update =
        |list: Value| json!({"baseConfigurationVersionId":version,"postLogoutRedirectUris":list});
    let (status, changed) = patch(&app, &cookie, &uri, update(json!([REPLACEMENT]))).await?;
    assert_eq!(status, StatusCode::OK, "{changed}");
    for invalid in [
        json!([ORIGINAL, "https://app.example/path#fragment"]),
        Value::Null,
    ] {
        let mut req = request(
            &uri,
            update(invalid),
            &cookie,
            "https://admin.aegaeon.test",
            true,
        );
        *req.method_mut() = Method::PATCH;
        assert!(app.clone().oneshot(req).await?.status().is_client_error());
    }
    let (status, preserved) = patch(
        &app,
        &cookie,
        &uri,
        json!({"baseConfigurationVersionId":version,"name":"Renamed"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        preserved["client"]["postLogoutRedirectUris"],
        json!([REPLACEMENT])
    );
    let mut read = request(&uri, json!({}), &cookie, "https://admin.aegaeon.test", true);
    *read.method_mut() = Method::GET;
    let response = app.clone().oneshot(read).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let read: Value = serde_json::from_slice(&body::to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(read["postLogoutRedirectUris"], json!([REPLACEMENT]));
    check_runtime(pool, &env, identifier).await?;
    let (status, cleared) = patch(&app, &cookie, &uri, update(json!([]))).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cleared["client"]["postLogoutRedirectUris"], json!([]));
    let after = crate::web::build_router(test_app_state(pool.clone(), &env).await?);
    assert_eq!(
        start_logout(&after, identifier, REPLACEMENT)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let legacy_identifier = default["client"]["clientIdentifier"]
        .as_str()
        .ok_or("legacy client")?;
    assert_eq!(
        start_logout(&after, legacy_identifier, REPLACEMENT)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let dynamic_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2",
    )
    .bind(env.environment_id)
    .bind("registered-by-dcr")
    .fetch_one(pool)
    .await?;
    let dynamic_uri = format!("{collection}/{dynamic_id}");
    let (status, dynamic) =
        patch(&app, &cookie, &dynamic_uri, update(json!([REPLACEMENT]))).await?;
    assert_eq!(status, StatusCode::OK, "{dynamic}");
    let reloaded = crate::web::build_router(test_app_state(pool.clone(), &env).await?);
    confirm_logout(&reloaded, &env, "registered-by-dcr").await?;
    assert_eq!(
        start_logout(&reloaded, "registered-by-dcr", ORIGINAL)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL management API and logout confirmation"]
async fn pg_managed_client_post_logout_redirects_reach_confirmed_browser_logout(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = check_registration(&pool).await;
    finish(result, cleanup(control, pool, &name).await)
}
