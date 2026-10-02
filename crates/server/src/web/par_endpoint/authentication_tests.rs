use super::super::test_support::{
    cleanup_test_environment, finish_test, sample_registered_client, setup_test_environment,
    test_app_state, test_pg_pool, update_test_policy, TestResult,
};
use super::super::AppState;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    Extension,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

const SECRET: &str = "par-storage-sentinel-secret";
const METHODS: [&str; 4] = [
    "none",
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
];

async fn fixture(
    pool: &sqlx::PgPool,
    env: &super::super::test_support::TestEnvironment,
) -> TestResult<AppState> {
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed = $1 WHERE environment_id = $2")
        .bind(METHODS.to_vec()).bind(env.environment_id).execute(pool).await?;
    let key = crate::oidc::OidcSigningKey::from_rsa_pem(
        "par-auth".into(),
        include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem"),
    )?;
    for method in METHODS {
        let mut client = sample_registered_client(method);
        client.token_endpoint_auth_method = method.into();
        if method.starts_with("client_secret") {
            client.client_secret = Some(SECRET.into());
        }
        if method == "private_key_jwt" {
            client.inline_jwks = Some(
                crate::client_registry::RegisteredClientJwks::from_value(
                    serde_json::to_value(key.jwks())?,
                    false,
                )
                .map_err(std::io::Error::other)?,
            );
        }
        crate::dcr_persistence::create_dynamic_registration(
            pool,
            &env.issuer_host,
            &client,
            &["code".into()],
            &format!("par-test-registration-{method}"),
            "par-test",
        )
        .await?;
    }
    let mut state = test_app_state(pool.clone(), env).await?;
    update_test_policy(&mut state, |policy| {
        policy.require_client_auth_par = false;
        policy.require_client_auth_token = false;
        policy.private_key_jwt_enabled = true;
    })
    .await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(env.environment_id);
    let store = Arc::new(
        crate::par::ParStore::try_new_from_shared_store_env_with_expires_in(90, &namespace)?,
    );
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?;
    state.protocol.par_endpoint = Arc::new(crate::par::ParEndpoint::new(
        Arc::new(crate::metrics_integration::MetricsIntegration::new(
            Arc::new(metrics),
        )),
        store.clone(),
    ));
    state.protocol.par_store = store;
    for method in METHODS {
        let client = state
            .clients
            .try_get(method)?
            .ok_or("registered client missing")?;
        state
            .protocol
            .par_endpoint
            .register_client(crate::par::Client {
                client_id: client.client_id,
                client_secret: None,
                token_endpoint_auth_method: client.token_endpoint_auth_method,
                redirect_uris: client.redirect_uris,
                allowed_scopes: client.allowed_scopes,
            });
    }
    Ok(state)
}

async fn send(
    state: &AppState,
    client: &str,
    auth: Option<&str>,
    extra: &[(&str, &str)],
) -> TestResult<(StatusCode, Value)> {
    let mut fields = vec![
        ("client_id", client),
        ("response_type", "code"),
        ("redirect_uri", "https://client.example.com/callback"),
        ("scope", "openid"),
        ("state", "par-state"),
        ("iss", state.issuer.as_str()),
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("code_challenge_method", "S256"),
    ];
    fields.extend_from_slice(extra);
    let mut request =
        Request::post("/par").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(auth) = auth {
        request = request.header(header::AUTHORIZATION, auth);
    }
    let app = super::super::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let response = app
        .oneshot(request.body(Body::from(serde_urlencoded::to_string(fields)?))?)
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?,
    ))
}

fn request_keys(state: &AppState, connection: &mut redis::Connection) -> TestResult<Vec<String>> {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let prefix = namespace.redis_atomic_group_prefix(
        crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
        "par",
        "v2",
    );
    Ok(redis::cmd("KEYS")
        .arg(format!("{prefix}:req:*"))
        .query(connection)?)
}

async fn rejected(
    state: &AppState,
    conn: &mut redis::Connection,
    client: &str,
    auth: Option<&str>,
    extra: &[(&str, &str)],
) -> TestResult {
    let before = request_keys(state, conn)?.len();
    let (status, body) = send(state, client, auth, extra).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    assert!(body.get("request_uri").is_none());
    assert_eq!(
        request_keys(state, conn)?.len(),
        before,
        "rejection must not persist a request"
    );
    Ok(())
}

fn assertion(state: &AppState) -> TestResult<String> {
    let now = crate::util::now_unix_epoch_secs()?;
    Ok(jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &json!({"iss":"private_key_jwt", "sub":"private_key_jwt", "aud":format!("{}/par",state.issuer),
            "iat":now,"exp":now+60,"jti":Uuid::new_v4().to_string()}),
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../tests/fixtures/rsa2048-private.pk8.pem"
        ))?,
    )?)
}

async fn exercise(state: &mut AppState) -> TestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let mut conn = redis::Client::open(url)?.get_connection()?;
    for method in &METHODS[1..] {
        rejected(state, &mut conn, method, None, &[]).await?;
        rejected(
            state,
            &mut conn,
            method,
            None,
            &[("client_authenticated", "true")],
        )
        .await?;
    }
    rejected(state, &mut conn, "unknown", None, &[]).await?;
    rejected(state, &mut conn, "none", Some("Bearer unsupported"), &[]).await?;
    rejected(state, &mut conn, "none", Some("Basic"), &[]).await?;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("client_secret_basic:{SECRET}"))
    );
    let wrong_method = format!(
        "Basic {}",
        STANDARD.encode(format!("client_secret_post:{SECRET}"))
    );
    rejected(
        state,
        &mut conn,
        "client_secret_post",
        Some(&wrong_method),
        &[],
    )
    .await?;
    let wrong = format!("Basic {}", STANDARD.encode("client_secret_basic:wrong"));
    rejected(state, &mut conn, "client_secret_basic", Some(&wrong), &[]).await?;
    rejected(
        state,
        &mut conn,
        "client_secret_basic",
        None,
        &[("client_secret", SECRET)],
    )
    .await?;
    rejected(state, &mut conn, "client_secret_post", Some(&basic), &[]).await?;
    rejected(
        state,
        &mut conn,
        "client_secret_post",
        None,
        &[("client_secret", "wrong")],
    )
    .await?;
    let (status, body) = send(
        state,
        "client_secret_basic",
        Some(&basic),
        &[("client_secret", SECRET)],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
    rejected(state, &mut conn, "none", None, &[("client_secret", SECRET)]).await?;
    let jwt = assertion(state)?;
    let assertion_fields = [
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", jwt.as_str()),
    ];
    rejected(
        state,
        &mut conn,
        "private_key_jwt",
        None,
        &[
            ("client_assertion_type", assertion_fields[0].1),
            ("client_assertion", "invalid"),
        ],
    )
    .await?;
    for (client, auth, fields) in [
        ("none", None, vec![]),
        ("none", None, vec![("client_secret", "")]),
        ("client_secret_basic", Some(basic.as_str()), vec![]),
        ("client_secret_post", None, vec![("client_secret", SECRET)]),
        ("private_key_jwt", None, assertion_fields.to_vec()),
    ] {
        let (status, body) = send(state, client, auth, &fields).await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        for key in request_keys(state, &mut conn)? {
            let payload: String = redis::cmd("GET").arg(key).query(&mut conn)?;
            assert!(!payload.contains(SECRET));
            assert!(serde_json::from_str::<Value>(&payload)?["request"]
                .get("client_secret")
                .is_none());
        }
        let uri = body["request_uri"].as_str().ok_or("request_uri missing")?;
        let reserved = state
            .protocol
            .par_store
            .reserve_request_for_client(uri, client)
            .map_err(|e| format!("{e:?}"))?;
        assert!(reserved.request.client_secret.is_none());
        assert_eq!(reserved.request.client_authenticated, client != "none");
        let resumed = state
            .protocol
            .par_store
            .resume_request_for_client(uri, client, &reserved.continuation)
            .map_err(|e| format!("{e:?}"))?;
        assert!(resumed.client_secret.is_none());
        state
            .protocol
            .par_store
            .try_consume_request(uri)
            .map_err(|e| format!("{e:?}"))?;
    }
    update_test_policy(state, |policy| policy.require_client_auth_par = true).await?;
    rejected(state, &mut conn, "none", None, &[]).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and AEGAEON_PAR_REDIS_URL / AEGAEON_TEST_REDIS_URL"]
async fn shared_redis_par_registered_authentication_and_secret_free_storage() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        exercise(&mut state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
