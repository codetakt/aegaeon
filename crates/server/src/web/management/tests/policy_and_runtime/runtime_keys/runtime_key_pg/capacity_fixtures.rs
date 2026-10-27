const CAPACITY_USAGES: [crate::runtime_keys::RuntimeKeyUsage; 4] = [
    crate::runtime_keys::RuntimeKeyUsage::OidcIdTokenSigning,
    crate::runtime_keys::RuntimeKeyUsage::OidcRequestObjectDecryption,
    crate::runtime_keys::RuntimeKeyUsage::JwtAccessTokenSigning,
    crate::runtime_keys::RuntimeKeyUsage::JwtIntrospectionSigning,
];

async fn capacity_pg_pool() -> Result<sqlx::PgPool, Box<dyn StdError>> {
    let url = std::env::var("AEGAEON_DATABASE_URL")?;
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .connect(&url)
        .await?)
}

fn capacity_create_request(
    env: &RuntimeKeyTestEnvironment,
    usage: crate::runtime_keys::RuntimeKeyUsage,
    kid: &str,
    activate: bool,
) -> Result<CreateRuntimeKeyRequest, Box<dyn StdError>> {
    let mut req = runtime_key_create_request(usage.as_db_str());
    req.base_configuration_version_id = env.configuration_version_id.to_string();
    req.kid = Some(kid.to_string());
    req.activate = activate;
    if matches!(
        usage,
        crate::runtime_keys::RuntimeKeyUsage::JwtAccessTokenSigning
            | crate::runtime_keys::RuntimeKeyUsage::JwtIntrospectionSigning
    ) {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()
            .map_err(|_| io::Error::other("capacity fixture key generation failed"))?;
        req.private_key_pem = Some(pkcs8_private_key_pem(key.pkcs8));
    }
    Ok(req)
}

fn capacity_activate_request(
    env: &RuntimeKeyTestEnvironment,
    usage: crate::runtime_keys::RuntimeKeyUsage,
) -> ActivateRuntimeKeyRequest {
    ActivateRuntimeKeyRequest {
        algorithm: None,
        base_configuration_version_id: env.configuration_version_id.to_string(),
        usage: usage.as_db_str().to_string(),
        comment: None,
    }
}

async fn capacity_post(
    app: &axum::Router,
    env: &RuntimeKeyTestEnvironment,
    sid: &str,
    suffix: &str,
    value: serde_json::Value,
) -> Result<Response, Box<dyn StdError>> {
    Ok(app
        .clone()
        .oneshot(membership_http_request(
            Method::POST,
            env,
            suffix,
            sid,
            value,
        )?)
        .await?)
}

async fn capacity_create_http(
    app: &axum::Router,
    env: &RuntimeKeyTestEnvironment,
    sid: &str,
    req: &CreateRuntimeKeyRequest,
) -> TestResult {
    let response = capacity_post(app, env, sid, "runtimeKeys", serde_json::to_value(req)?).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    Ok(())
}

async fn capacity_loaded(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    usage: crate::runtime_keys::RuntimeKeyUsage,
    kid: &str,
    retiring: usize,
) -> TestResult {
    let mut tx = pool.begin().await?;
    let keys = crate::runtime_keys::load_runtime_key_set_for_environment_in_tx(
        &mut tx,
        env.environment_id,
    )
    .await?;
    assert_eq!(
        keys.active_key(usage).map(|key| key.kid.as_str()),
        Some(kid)
    );
    assert_eq!(keys.retiring_keys(usage).count(), retiring);
    tx.rollback().await?;
    Ok(())
}

async fn capacity_refused(
    response: Response,
    usage: crate::runtime_keys::RuntimeKeyUsage,
) -> TestResult {
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = response_json(response).await?;
    assert_eq!(body["errorCode"], "conflict");
    assert_eq!(
        body["message"],
        "Runtime key rotation exceeds retiring key capacity"
    );
    assert_eq!(
        body["details"],
        serde_json::json!({"usage": usage.as_db_str(), "liveRetiringCount": 4, "prospectiveRetiringCount": 5, "limit": 4})
    );
    assert!(body["requestId"].is_string());
    Ok(())
}

async fn capacity_unchanged(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    before: &[serde_json::Value],
) -> TestResult {
    // Do not print snapshots: rows contain encrypted handles and configuration.
    assert!(
        before == configuration_transition_snapshot(pool, env).await?,
        "refused mutation changed stored state or audit"
    );
    Ok(())
}

async fn capacity_revoke_active(
    app: &axum::Router,
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    sid: &str,
    usage: crate::runtime_keys::RuntimeKeyUsage,
) -> TestResult {
    let id: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.runtime_keys WHERE environment_id=$1 AND usage=$2::aegaeon.runtime_key_usage AND status='ACTIVE'")
        .bind(env.environment_id).bind(usage.as_db_str()).fetch_one(pool).await?;
    let response = capacity_post(
        app,
        env,
        sid,
        &format!("runtimeKeys/{id}/revoke"),
        serde_json::json!({"baseConfigurationVersionId":env.configuration_version_id}),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}
