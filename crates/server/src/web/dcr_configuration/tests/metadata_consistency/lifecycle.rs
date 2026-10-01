use super::*;

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let app = router(pool, env).await?;
    let default = post(
        &app,
        &json!({"redirect_uris":["HTTPS://CLIENT.EXAMPLE:443/%63allback"],"pkce_required":true}),
    )
    .await?;
    assert_eq!(default["grant_types"], json!(["authorization_code"]));
    assert_eq!(default["response_types"], json!(["code"]));
    assert_eq!(
        default["redirect_uris"],
        json!(["HTTPS://CLIENT.EXAMPLE:443/%63allback"])
    );
    assert_eq!(
        read(&app, &default).await?["grant_types"],
        default["grant_types"]
    );
    let mut credentials = post(
        &app,
        &json!({"grant_types":["client_credentials"],"pkce_required":true}),
    )
    .await?;
    assert_eq!(credentials["response_types"], json!([]));
    assert_eq!(credentials["redirect_uris"], json!([]));
    let client = field(&credentials, "client_id")?.to_owned();
    let secret:String=sqlx::query_scalar("SELECT s.secret_hash FROM aegaeon.client_secrets s JOIN aegaeon.clients c ON c.id=s.client_id WHERE c.client_identifier=$1 AND s.status='ACTIVE'").bind(&client).fetch_one(pool).await?;
    credentials = inherit_empty_responses(&app, credentials).await?;
    let before = digest(pool, env).await?;
    let mut transition = json!({"client_id":client,"grant_types":["authorization_code"],"redirect_uris":["https://client.example/callback"],"pkce_required":true});
    let response = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/register/{client}"),
            Some(field(&credentials, "registration_access_token")?),
            &transition,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await?["error"],
        "invalid_client_metadata"
    );
    assert_eq!(before, digest(pool, env).await?);
    transition["response_types"] = json!(["code"]);
    let response = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/register/{client}"),
            Some(field(&credentials, "registration_access_token")?),
            &transition,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    credentials = response_json(response).await?;
    assert_eq!(credentials["response_types"], json!(["code"]));
    let current:String=sqlx::query_scalar("SELECT s.secret_hash FROM aegaeon.client_secrets s JOIN aegaeon.clients c ON c.id=s.client_id WHERE c.client_identifier=$1 AND s.status='ACTIVE'").bind(&client).fetch_one(pool).await?;
    assert_eq!(
        secret, current,
        "valid owner update preserves active client secret"
    );
    let reloaded = router(pool, env).await?;
    assert_eq!(
        read(&reloaded, &credentials).await?["response_types"],
        json!(["code"])
    );
    let stored = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        &client,
        field(&credentials, "registration_access_token")?,
    )
    .await?
    .ok_or("stored")?;
    assert_eq!(stored.response_types, vec!["code"]);
    transition_to_non_code(&reloaded, &credentials, pool, env).await?;
    let device=post(&reloaded,&json!({"grant_types":[DEVICE_CODE_GRANT_TYPE],"response_types":[],"redirect_uris":[],"token_endpoint_auth_method":"none","pkce_required":true})).await?;
    assert_eq!(device["response_types"], json!([]));
    assert_eq!(read(&reloaded, &device).await?["response_types"], json!([]));
    Ok(())
}

async fn inherit_empty_responses(app: &axum::Router, mut credentials: Value) -> TestResult<Value> {
    let client = field(&credentials, "client_id")?.to_owned();
    for extra in [
        json!({}),
        json!({"response_types":null}),
        json!({"response_types":[]}),
    ] {
        let mut body = extra;
        body["client_id"] = json!(client);
        body["pkce_required"] = json!(true);
        let old = field(&credentials, "registration_access_token")?.to_owned();
        let response = app
            .clone()
            .oneshot(request(
                Method::PUT,
                &format!("/register/{client}"),
                Some(&old),
                &body,
            )?)
            .await?;
        let status = response.status();
        credentials = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "{credentials}");
        assert_eq!(credentials["response_types"], json!([]));
        assert_ne!(field(&credentials, "registration_access_token")?, old);
        let rejected = app
            .clone()
            .oneshot(registration_request(
                Method::GET,
                &client,
                Some(&old),
                None,
            )?)
            .await?;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    }
    Ok(credentials)
}

async fn transition_to_non_code(
    app: &axum::Router,
    credentials: &Value,
    pool: &PgPool,
    env: &TestDcrEnvironment,
) -> TestResult {
    let client = field(credentials, "client_id")?;
    let token = field(credentials, "registration_access_token")?;
    let mut update = json!({"client_id":client,"grant_types":["client_credentials"],"redirect_uris":[],"pkce_required":true});
    let before = digest(pool, env).await?;
    let refused = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/register/{client}"),
            Some(token),
            &update,
        )?)
        .await?;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(digest(pool, env).await?, before);
    update["response_types"] = json!([]);
    let accepted = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/register/{client}"),
            Some(token),
            &update,
        )?)
        .await?;
    assert_eq!(accepted.status(), StatusCode::OK);
    let updated = response_json(accepted).await?;
    assert_eq!(updated["response_types"], json!([]));
    assert_eq!(read(app, &updated).await?["response_types"], json!([]));
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB and native DCR parser; disposable desired-schema database"]
async fn dcr_metadata_router_defaults_empty_inheritance_transitions_and_secret_preservation(
) -> TestResult {
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_dcr_environment(&db.pool).await?;
        scenario(&db.pool, &env).await
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
