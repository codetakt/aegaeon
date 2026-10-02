use super::*;
use crate::dcr_persistence::{load_dynamic_registration_by_token, DcrStoredClient};

pub(super) async fn stored(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    value: &Value,
) -> TestResult<DcrStoredClient> {
    load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        field(value, "client_id")?,
        field(value, "registration_access_token")?,
    )
    .await?
    .ok_or_else(|| io::Error::other("registration missing").into())
}

pub(super) async fn put(
    app: &axum::Router,
    current: &Value,
    value: &Value,
) -> TestResult<Response> {
    let mut value = value.clone();
    if current["token_endpoint_auth_method"] == "private_key_jwt"
        && value.get("token_endpoint_auth_method").is_none()
    {
        // This fixture explicitly supplies its unchanged key source. General
        // omitted-key metadata roundtrip behavior is outside this credential test.
        value["jwks_uri"] = json!("https://client.example/jwks");
    }
    Ok(app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/register/{}", field(current, "client_id")?),
            Some(field(current, "registration_access_token")?),
            &value,
        )?)
        .await?)
}

pub(super) async fn accepted(
    app: &axum::Router,
    current: &Value,
    value: &Value,
) -> TestResult<Value> {
    let response = put(app, current, value).await?;
    let status = response.status();
    let value = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "{}", value["error"]);
    Ok(value)
}

pub(super) async fn issue(pool: &PgPool, stored: &DcrStoredClient, secret: &str) -> TestResult {
    let hash = crate::local_credentials::hash_password(secret).map_err(io::Error::other)?;
    // Fixture writer uses the same environment/client serialization as management.
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
        .bind(stored.environment_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM aegaeon.clients WHERE id=$1 FOR UPDATE")
        .bind(stored.database_client_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO aegaeon.client_secrets(environment_id,client_id,configuration_version_id,secret_hash,secret_hash_algorithm,expires_at) VALUES($1,$2,$3,$4,'argon2id',statement_timestamp()+interval '1 hour')")
        .bind(stored.environment_id).bind(stored.database_client_id).bind(stored.configuration_version_id).bind(hash).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn refusals(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    app: &axum::Router,
    registry: &crate::client_registry::ClientRegistry,
    current: &Value,
) -> TestResult {
    let id = field(current, "client_id")?;
    let mut cases = vec![json!({})];
    for value in [
        Value::Null,
        json!(""),
        json!("other"),
        json!(42),
        json!([]),
        json!({}),
        json!(true),
    ] {
        cases.push(json!({"client_id":value}));
    }
    for value in [
        Value::Null,
        json!(""),
        json!(" "),
        json!("private-sentinel"),
        json!(42),
        json!([]),
        json!({}),
        json!(false),
    ] {
        cases.push(json!({"client_id":id,"client_secret":value}));
    }
    for name in [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
    ] {
        for value in [Value::Null, json!("private-sentinel")] {
            let mut body = json!({"client_id":id});
            body[name] = value;
            cases.push(body);
        }
    }
    let row = stored(pool, env, current).await?;
    if let Some(hash) = sqlx::query_scalar::<_, String>(
        "SELECT secret_hash FROM aegaeon.client_secrets WHERE client_id=$1 LIMIT 1",
    )
    .bind(row.database_client_id)
    .fetch_optional(pool)
    .await?
    {
        cases.push(json!({"client_id":id,"client_secret":hash}));
    }
    for value in cases {
        let before = digest(pool, env).await?;
        let runtime = registry.try_runtime_snapshot_fingerprint()?;
        assert!(runtime.is_some(), "runtime projection must be populated");
        let response = put(app, current, &value).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let error = response_json(response).await?;
        assert_eq!(error["error"], "invalid_client_metadata");
        let text = error.to_string();
        assert!(!text.contains("private-sentinel") && !text.contains("$argon2"));
        assert_eq!(before, digest(pool, env).await?);
        assert_eq!(runtime, registry.try_runtime_snapshot_fingerprint()?);
        read(app, current).await?;
    }
    // Authentication precedes malformed JSON and invalid credential members.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/register/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer wrong-token")
                .body(Body::from("{invalid private-sentinel"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!response_json(response)
        .await?
        .to_string()
        .contains("private-sentinel"));
    for raw in [
        format!(
            r#"{{"client_id":"{id}","client_secret":"private-sentinel","client_\u0073ecret":"private-sentinel"}}"#
        ),
        format!(r#"{{"client_id":"{id}","require_pkce":true,"pkce_required":true}}"#),
    ] {
        let before = digest(pool, env).await?;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/register/{id}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", field(current, "registration_access_token")?),
                    )
                    .body(Body::from(raw))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await?["error"],
            "invalid_client_metadata"
        );
        assert_eq!(before, digest(pool, env).await?);
    }
    Ok(())
}

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    drop(router(pool, env).await?);
    let mut state = test_app_state(pool.clone(), env).await?;
    state.dcr_allowed_algs = std::sync::Arc::new(["RS256".to_string()].into_iter().collect());
    let registry = state.clients.clone();
    let app = crate::web::router::build_router(state);
    for method in [
        "client_secret_basic",
        "client_secret_post",
        "none",
        "private_key_jwt",
    ] {
        let mut metadata = json!({"redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":method,"pkce_required":true});
        if method == "private_key_jwt" {
            metadata["jwks_uri"] = json!("https://client.example/jwks");
            metadata["token_endpoint_auth_signing_alg"] = json!("RS256");
        }
        let mut current = post(&app, &metadata).await?;
        let id = field(&current, "client_id")?.to_owned();
        let secret = current["client_secret"].as_str().map(str::to_owned);
        refusals(pool, env, &app, &registry, &current).await?;
        // An unrelated extension is ignored; absence adds no secret condition.
        current = accepted(
            &app,
            &current,
            &json!({"client_id":id,"unknown_extension":{"x":1},"pkce_required":true}),
        )
        .await?;
        if let Some(secret) = secret {
            current = accepted(
                &app,
                &current,
                &json!({"client_id":id,"client_secret":secret,"pkce_required":true}),
            )
            .await?;
            assert!(current.get("client_secret").is_none());
            assert!(crate::client_registry::verify_client_secret_credentials(
                &secret,
                &registry.client_secret_credentials(&id)
            ));
            // Equality is checked against credentials before transitioning to public.
            current=accepted(&app,&current,&json!({"client_id":id,"client_secret":secret,"token_endpoint_auth_method":"none","pkce_required":true})).await?;
            assert!(current.get("client_secret").is_none());
        }
        let before = digest(pool, env).await?;
        let refused=put(&app,&current,&json!({"client_id":id,"client_secret":"private-sentinel","token_endpoint_auth_method":"client_secret_basic","pkce_required":true})).await?;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(before, digest(pool, env).await?);
        current=accepted(&app,&current,&json!({"client_id":id,"token_endpoint_auth_method":"client_secret_basic","pkce_required":true})).await?;
        assert!(!field(&current, "client_secret")?.is_empty());
        assert_ne!(field(&current, "client_secret")?, "private-sentinel");
        let audit: Value = sqlx::query_scalar(
            "SELECT jsonb_agg(to_jsonb(a)) FROM aegaeon.audit_events a WHERE environment_id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(pool)
        .await?;
        assert!(!audit.to_string().contains("private-sentinel"));
        assert!(!audit
            .to_string()
            .contains(field(&current, "client_secret")?));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; mounted router and actual Argon2 credentials"]
async fn owner_put_credentials_http_admission_and_state_preservation() -> TestResult {
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
