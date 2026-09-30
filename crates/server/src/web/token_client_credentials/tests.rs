//! Required-service tests exercise the production token/introspection handlers and admission guard.
use crate::management::types::{PolicyDocument, PolicySenderConstraint};
use crate::policy::TOKEN_EXCHANGE_GRANT_TYPE;
use crate::web::{test_support::*, AppState};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    middleware,
    routing::post,
    Extension, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;

const CALLER: &str = "service-caller";
const RS: &str = "resource-reader";
const TARGET: &str = "orders";
const SECRET: &str = "private-caller-fixture-secret";
const RS_SECRET: &str = "private-resource-reader-fixture-secret";
fn credential(client: &str) -> &'static str {
    match client {
        CALLER => SECRET,
        RS => RS_SECRET,
        TARGET => "private-audience-client-fixture-secret",
        _ => "private-unrelated-client-fixture-secret",
    }
}
const ALIAS: &str = "https://resource.example/orders";

fn policy(jwt: bool) -> TestResult<PolicyDocument> {
    Ok(PolicyDocument {
        sender_constraint: PolicySenderConstraint::None,
        jwt_access_tokens_enabled: jwt,
        allowed_grant_types: vec![
            "authorization_code".into(),
            "client_credentials".into(),
            TOKEN_EXCHANGE_GRANT_TYPE.into(),
        ],
        token_exchange: serde_json::from_value(json!({"version":1,"targets":[
            {"audience":TARGET,"resourceAliases":[ALIAS]}, {"audience":"closed","resourceAliases":["https://resource.example/closed"]}
        ],"rules":[]}))?,
        client_credentials: serde_json::from_value(json!({"version":1,"resourceServers":[
            {"targetAudience":TARGET,"introspectionClients":[RS]}
        ],"rules":[{"clientId":CALLER,"targetAudience":TARGET,"scopes":["api.read","api.write"],"defaultScopes":["api.read"],"defaultTarget":false}]}))?,
        ..PolicyDocument::default()
    })
}

async fn register(pool: &PgPool, env: &TestEnvironment, id: &str, secret: &str) -> TestResult {
    let mut client = sample_registered_client(id);
    client.client_secret = Some(secret.into());
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.allowed_scopes = vec!["api.read".into(), "api.write".into(), "unrelated".into()];
    client.allowed_grant_types = vec![
        "authorization_code".into(),
        "client_credentials".into(),
        TOKEN_EXCHANGE_GRANT_TYPE.into(),
    ];
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        &uuid::Uuid::new_v4().to_string(),
        "cc-http-fixture",
    )
    .await?;
    Ok(())
}

async fn install_policy(
    pool: &PgPool,
    env: &TestEnvironment,
    policy: &PolicyDocument,
) -> TestResult {
    // Fixture preparation; management API roundtrip/activation has separate tests.
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document = jsonb_set(configuration_document, '{policy}', $1) WHERE environment_id = $2 AND status = 'ACTIVE'")
        .bind(serde_json::to_value(policy)?).bind(env.environment_id).execute(pool).await?;
    Ok(())
}

pub(in crate::web) async fn reload(
    state: &AppState,
    env: &TestEnvironment,
) -> TestResult<AppState> {
    let value:Value=sqlx::query_scalar("SELECT configuration_document->'policy' FROM aegaeon.configuration_versions WHERE environment_id=$1 AND status='ACTIVE'")
        .bind(env.environment_id).fetch_one(&state.db_pool).await?;
    let policy: PolicyDocument = serde_json::from_value(value)?;
    let mut loaded = test_app_state(state.db_pool.clone(), env).await?;
    Arc::make_mut(&mut loaded.cfg).apply_management_policy(&policy)?;
    loaded.keys = state.keys.clone();
    loaded.tokens = state.tokens.clone();
    Ok(loaded)
}

pub(in crate::web) async fn fixture(
    pool: &PgPool,
    env: &TestEnvironment,
    jwt: bool,
    redis: bool,
) -> TestResult<AppState> {
    for id in [CALLER, RS, TARGET, "unrelated-client"] {
        register(pool, env, id, credential(id)).await?;
    }
    let policy = policy(jwt)?;
    install_policy(pool, env, &policy).await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1, token_endpoint_auth_methods_allowed=$2 WHERE environment_id=$3")
        .bind(&policy.allowed_grant_types).bind(vec!["client_secret_basic", "none"]).bind(env.environment_id).execute(pool).await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    Arc::make_mut(&mut state.cfg).apply_management_policy(&policy)?;
    state.keys.access_token = Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?);
    if redis {
        crate::web::token_exchange::tests::use_redis(&mut state)?;
    } else {
        state.tokens.issuer = Arc::new(
            crate::authcode::TokenIssuer::with_stores(
                state.keys.access_token.clone(),
                crate::authcode::AuthCodeStore::new_process_local_for_tests(),
                state.tokens.store.as_ref().clone(),
            )
            .with_issuer(env.issuer_url.clone())
            .with_jwt_access_tokens_enabled(jwt),
        );
        state.tokens.validator = Arc::new(
            crate::authcode::TokenValidator::with_policy(
                state.tokens.store.as_ref().clone(),
                state.keys.access_token.clone(),
                state.cfg.security_policy,
            )
            .with_issuer(Some(env.issuer_url.clone()))
            .with_jwt_access_tokens_enabled(jwt),
        );
    }
    Ok(state)
}

pub(in crate::web) async fn request(
    state: &AppState,
    path: &str,
    client: &str,
    secret: &str,
    params: &[(&str, &str)],
) -> TestResult<(StatusCode, Value)> {
    let app = Router::new()
        .route("/token", post(crate::web::token_endpoint::token))
        .route("/introspect", post(crate::web::token_lifecycle::introspect))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::web::runtime_authority_guard::runtime_authority_guard_middleware,
        ))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12454,
        )))))
        .with_state(state.clone());
    let response = app
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(format!("{client}:{secret}"))),
                )
                .body(Body::from(serde_urlencoded::to_string(params)?))?,
        )
        .await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    Ok((status, body))
}

async fn introspect(state: &AppState, client: &str, token: &str) -> TestResult<Value> {
    let (status, body) = request(
        state,
        "/introspect",
        client,
        credential(client),
        &[("token", token)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body)
}

async fn scenario(pool: &PgPool, env: &TestEnvironment, jwt: bool, redis: bool) -> TestResult {
    let state = fixture(pool, env, jwt, redis).await?;
    for (client, wrong_secret) in [(CALLER, RS_SECRET), (RS, SECRET)] {
        let (status, body) = request(
            &state,
            "/token",
            client,
            wrong_secret,
            &[("grant_type", "client_credentials"), ("audience", TARGET)],
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "cross-client credential use: {body}"
        );
        assert_eq!(body["error"], "invalid_client");
    }
    let mut issued = Vec::new();
    for selector in [("audience", TARGET), ("resource", ALIAS)] {
        let (status, body) = request(
            &state,
            "/token",
            CALLER,
            SECRET,
            &[
                ("grant_type", "client_credentials"),
                selector,
                ("scope", "api.read api.write"),
            ],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("refresh_token").is_none());
        let token = body["access_token"]
            .as_str()
            .ok_or("token missing")?
            .to_string();
        let rs = introspect(&state, RS, &token).await?;
        assert_eq!(rs["active"], true);
        assert_eq!(rs["aud"], TARGET);
        assert_eq!(rs["client_id"], CALLER);
        assert_eq!(rs["sub"], CALLER);
        assert_eq!(introspect(&state, CALLER, &token).await?["active"], true);
        assert_eq!(
            introspect(&state, TARGET, &token).await?["active"],
            false,
            "audience-equal client gets no permission"
        );
        assert_eq!(
            introspect(&state, "unrelated-client", &token).await?["active"],
            false
        );
        issued.push(token);
    }
    let token = &issued[0];
    for (client, params, error) in [
        (
            CALLER,
            vec![("grant_type", "client_credentials")],
            "invalid_target",
        ),
        (
            CALLER,
            vec![
                ("grant_type", "client_credentials"),
                ("audience", "unknown"),
            ],
            "invalid_target",
        ),
        (
            CALLER,
            vec![
                ("grant_type", "client_credentials"),
                ("resource", "https://resource.example/closed"),
            ],
            "invalid_target",
        ),
        (
            RS,
            vec![("grant_type", "client_credentials"), ("resource", ALIAS)],
            "invalid_target",
        ),
        (
            CALLER,
            vec![
                ("grant_type", "client_credentials"),
                ("audience", TARGET),
                ("audience", TARGET),
            ],
            "invalid_target",
        ),
        (
            CALLER,
            vec![
                ("grant_type", "client_credentials"),
                ("resource", ALIAS),
                ("resource", ALIAS),
            ],
            "invalid_target",
        ),
        (
            CALLER,
            vec![
                ("grant_type", "client_credentials"),
                ("audience", TARGET),
                ("resource", "https://resource.example/closed"),
            ],
            "invalid_target",
        ),
        (
            CALLER,
            vec![
                ("grant_type", "client_credentials"),
                ("audience", TARGET),
                ("scope", "unrelated"),
            ],
            "invalid_scope",
        ),
        (
            CALLER,
            vec![
                ("grant_type", "client_credentials"),
                ("audience", TARGET),
                ("scope", "openid"),
            ],
            "invalid_scope",
        ),
        (
            CALLER,
            vec![
                ("grant_type", "client_credentials"),
                ("audience", TARGET),
                ("scope", "offline_access"),
            ],
            "invalid_scope",
        ),
    ] {
        let (status, body) = request(&state, "/token", client, credential(client), &params).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], error);
    }
    let (status, defaults) = request(
        &state,
        "/token",
        CALLER,
        SECRET,
        &[
            ("grant_type", "client_credentials"),
            ("audience", TARGET),
            ("resource", ALIAS),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{defaults}");
    assert_eq!(defaults["scope"], "api.read");
    let (status, exchange) = request(
        &state,
        "/token",
        CALLER,
        SECRET,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", token),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", TARGET),
            ("scope", "api.read"),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{exchange}");
    let derived = exchange["access_token"]
        .as_str()
        .ok_or("derived token missing")?;
    assert_eq!(introspect(&state, RS, derived).await?["active"], true);
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta_async(derived.to_string())
        .await?
        .ok_or("metadata missing")?;
    assert_eq!(meta.granted_scopes, ["api.read"]);
    assert!(meta.client_credentials_grant.is_some());
    assert!(meta.exchange_grant.is_none() && meta.refresh_parent.is_none());

    // A raw legacy token never obtains independent RS permission from current policy.
    let legacy = crate::authcode::types::AccessToken::new(
        CALLER.into(),
        CALLER.into(),
        Some("api.read".into()),
        300,
    );
    let legacy_id = legacy.token.clone();
    let mut legacy_meta = state
        .tokens
        .store
        .try_get_bearer_meta_async(token.to_string())
        .await?
        .ok_or("metadata missing")?;
    legacy_meta.token_id = legacy_id.clone();
    legacy_meta.client_credentials_grant = None;
    legacy_meta.granted_scopes = vec!["api.read".into()];
    legacy_meta.issued_at = legacy.created_at;
    legacy_meta.expires_at = legacy.created_at + std::time::Duration::from_secs(300);
    state
        .tokens
        .store
        .store_issued_grant_async(legacy, None, legacy_meta)
        .await?;
    assert_eq!(introspect(&state, RS, &legacy_id).await?["active"], false);

    // Marked records cannot obtain owner visibility when metadata is missing or mismatched.
    let mut missing = crate::authcode::types::AccessToken::new(
        CALLER.into(),
        CALLER.into(),
        Some("api.read".into()),
        300,
    );
    missing.client_credentials_digest = Some("0".repeat(64));
    let missing_id = missing.token.clone();
    state
        .tokens
        .store
        .try_replace_access_token_record(missing)?;
    assert_eq!(
        introspect(&state, CALLER, &missing_id).await?["active"],
        false
    );
    let mut bad = state
        .tokens
        .store
        .try_get_bearer_meta_async(issued[1].clone())
        .await?
        .ok_or("metadata missing")?;
    bad.client_credentials_grant
        .as_mut()
        .ok_or("grant missing")?
        .configuration_version_id = uuid::Uuid::new_v4();
    state.tokens.store.try_replace_bearer_meta_record(bad)?;
    assert_eq!(
        introspect(&state, CALLER, &issued[1]).await?["active"],
        false
    );

    // Current registration scope ceilings also invalidate already-issued authority.
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=ARRAY['api.read'] WHERE environment_id=$1 AND client_identifier=$2")
        .bind(env.environment_id).bind(CALLER).execute(pool).await?;
    assert_eq!(introspect(&state, CALLER, token).await?["active"], false);
    assert_eq!(
        introspect(&state, RS, derived).await?["active"],
        true,
        "attenuated scopes remain within the new ceiling"
    );
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=ARRAY['api.read','api.write','unrelated'] WHERE environment_id=$1 AND client_identifier=$2")
        .bind(env.environment_id).bind(CALLER).execute(pool).await?;
    assert_eq!(introspect(&state, RS, token).await?["active"], true);

    // Confidential method and effective profile CC eligibility remain required online.
    sqlx::query("UPDATE aegaeon.clients SET token_endpoint_authentication_method='none' WHERE environment_id=$1 AND client_identifier=$2")
        .bind(env.environment_id).bind(CALLER).execute(pool).await?;
    assert_eq!(introspect(&state, RS, token).await?["active"], false);
    sqlx::query("UPDATE aegaeon.clients SET token_endpoint_authentication_method='client_secret_basic' WHERE environment_id=$1 AND client_identifier=$2")
        .bind(env.environment_id).bind(CALLER).execute(pool).await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=ARRAY['authorization_code'] WHERE environment_id=$1")
        .bind(env.environment_id).execute(pool).await?;
    assert_eq!(introspect(&state, RS, token).await?["active"], false);
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1 WHERE environment_id=$2")
        .bind(&policy(jwt)?.allowed_grant_types)
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    assert_eq!(introspect(&state, RS, token).await?["active"], true);

    // Unrelated configuration edits need a reload but preserve selected authority.
    let mut revised = policy(jwt)?;
    revised.access_token_time_to_live_seconds += 1;
    install_policy(pool, env, &revised).await?;
    let (status, _) = request(&state, "/introspect", RS, RS_SECRET, &[("token", token)]).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let state = reload(&state, env).await?;
    assert_eq!(introspect(&state, RS, token).await?["active"], true);
    revised.client_credentials.resource_servers[0]
        .introspection_clients
        .clear();
    install_policy(pool, env, &revised).await?;
    let state = reload(&state, env).await?;
    assert_eq!(
        introspect(&state, CALLER, token).await?["active"],
        false,
        "owner fast path must not bypass changed authority"
    );
    assert_eq!(introspect(&state, RS, derived).await?["active"], false);
    revised.client_credentials.rules[0].default_target = true;
    install_policy(pool, env, &revised).await?;
    let state = reload(&state, env).await?;
    let (status, body) = request(
        &state,
        "/token",
        CALLER,
        SECRET,
        &[("grant_type", "client_credentials")],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "explicit default target: {body}");
    let default_token = body["access_token"]
        .as_str()
        .ok_or("default token missing")?;
    assert_eq!(
        introspect(&state, CALLER, default_token).await?["active"],
        true
    );
    assert_eq!(
        introspect(&state, RS, default_token).await?["active"],
        false,
        "empty explicit RS list grants no independent visibility"
    );
    revised.client_credentials.rules[0].default_scopes.clear();
    install_policy(pool, env, &revised).await?;
    let state = reload(&state, env).await?;
    let (status, body) = request(
        &state,
        "/token",
        CALLER,
        SECRET,
        &[("grant_type", "client_credentials")],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");
    revised.client_credentials = Default::default();
    install_policy(pool, env, &revised).await?;
    let state = reload(&state, env).await?;
    let (status, body) = request(
        &state,
        "/token",
        CALLER,
        SECRET,
        &[("grant_type", "client_credentials"), ("resource", ALIAS)],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target");
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL"]
async fn client_credentials_http_opaque_and_jwt_contract() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required; this test must not silently skip")?;
    for jwt in [false, true] {
        let env = setup_test_environment(&pool).await?;
        let result = scenario(&pool, &env, jwt, false).await;
        finish_test(result, cleanup_test_environment(&pool, &env).await)?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn client_credentials_http_shared_redis_contract() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required; this test must not silently skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = scenario(&pool, &env, true, true).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn replace_registration(pool: &PgPool, env: &TestEnvironment, id: &str) -> TestResult {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM aegaeon.client_secrets WHERE client_id IN (SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2)")
        .bind(env.environment_id).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM aegaeon.dynamic_client_registrations WHERE client_id IN (SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2)")
        .bind(env.environment_id).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2")
        .bind(env.environment_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    register(pool, env, id, "replacement-private-fixture-secret").await
}

async fn identity_scenario(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let state = fixture(pool, env, false, false).await?;
    let (status, body) = request(
        &state,
        "/token",
        CALLER,
        SECRET,
        &[("grant_type", "client_credentials"), ("audience", TARGET)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().ok_or("token missing")?;
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta_async(token.to_string())
        .await?
        .ok_or("metadata missing")?;
    let headers = axum::http::HeaderMap::from_iter([(
        header::AUTHORIZATION,
        format!("Basic {}", STANDARD.encode(format!("{CALLER}:{SECRET}"))).parse()?,
    )]);
    let params = vec![
        ("grant_type".into(), "client_credentials".into()),
        ("audience".into(), TARGET.into()),
    ];
    let (ctx, captured) = crate::web::token_endpoint::build_token_context(
        &state,
        &"/token".parse()?,
        &headers,
        params,
        &env.issuer_url,
        "identity-race".into(),
    )
    .await
    .map_err(|response| format!("capture returned {}", response.status()))?;
    let caller_before = captured.clients.try_get(CALLER)?.ok_or("caller missing")?;
    assert_eq!(caller_before.client_id, CALLER);
    assert!(
        captured.clients.try_get(RS)?.is_none(),
        "request snapshot copies only the selected authentication ID"
    );
    replace_registration(pool, env, CALLER).await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(pool, state.clients.as_ref())
        .await?;
    let denied = crate::web::client_credentials_authorization::authorize(&captured, &ctx)
        .await
        .expect_err("old authenticated credentials must not bind to the replacement UUID");
    assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !crate::web::client_credentials_authorization::current(&state, &meta)
            .await
            .map_err(|response| format!("currentness returned {}", response.status()))?
    );
    assert_eq!(introspect(&state, RS, token).await?["active"], false);
    let (status, body) = request(
        &state,
        "/token",
        CALLER,
        "replacement-private-fixture-secret",
        &[("grant_type", "client_credentials"), ("audience", TARGET)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fresh = body["access_token"]
        .as_str()
        .ok_or("replacement token missing")?;
    assert_eq!(introspect(&state, RS, fresh).await?["active"], true);
    replace_registration(pool, env, RS).await?;
    let (status, body) = request(
        &state,
        "/introspect",
        RS,
        "replacement-private-fixture-secret",
        &[("token", fresh)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["active"], false,
        "replacement RS identity cannot inherit old token visibility"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL"]
async fn client_credentials_authentication_snapshot_rejects_identity_substitution() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = identity_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires private PostgreSQL"]
async fn client_credentials_application_identity_composition_with_one_connection() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env, false, false).await?;
        state.application_authority = Some(crate::application_authorization::Authority {
            projections: pool.clone(),
            memberships: None,
        });
        let (id, _) = seed_test_projection(
            &pool,
            &env,
            CALLER,
            CALLER,
            json!([TARGET]),
            json!({"roles":["USER"],"organization_roles":[]}),
        )
        .await?;
        let (status, body) = request(
            &state,
            "/token",
            CALLER,
            SECRET,
            &[("grant_type", "client_credentials"), ("audience", TARGET)],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "pool1 CC publication: {body}");
        let token = body["access_token"].as_str().ok_or("token missing")?;
        let meta = state
            .tokens
            .store
            .try_get_bearer_meta_async(token.to_string())
            .await?
            .ok_or("metadata missing")?;
        let app = meta
            .application_grant
            .as_ref()
            .ok_or("application grant missing")?;
        let cc = meta
            .client_credentials_grant
            .clone()
            .ok_or("CC grant missing")?;
        assert_eq!(cc.caller.registration_id, id);
        let permit =
            crate::policy::client_credentials::AuthorizedClientCredentials::new(cc.clone())?;
        let mut guard = crate::application_authorization::store::lock_current(
            &pool,
            env.environment_id,
            &env.issuer_url,
            app,
        )
        .await?
        .ok_or("guard missing")?;
        crate::web::client_credentials_authorization::bind_application_identity(
            &state,
            &permit,
            Some(app),
            Some(&mut guard),
        )
        .await
        .map_err(|response| format!("identity check returned {}", response.status()))?;
        let mut wrong = cc;
        wrong.caller.registration_id = uuid::Uuid::new_v4();
        let wrong = crate::policy::client_credentials::AuthorizedClientCredentials::new(wrong)?;
        let denied = crate::web::client_credentials_authorization::bind_application_identity(
            &state,
            &wrong,
            Some(app),
            Some(&mut guard),
        )
        .await
        .expect_err("different CC identity must not acquire the locked projection");
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
        assert!(
            crate::web::client_credentials_authorization::bind_application_identity(
                &state,
                &permit,
                Some(app),
                None
            )
            .await
            .is_err()
        );
        drop(guard);
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
