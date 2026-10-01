//! Real signatures and actual routes; required PostgreSQL never silently skips.
mod client_auth_errors;
mod error_encoding;
mod negative;
mod oauth_forms;
mod oauth_grants;
mod par;
mod pkce;
mod resources;
mod success;
use super::test_support::*;
use super::AppState;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, HeaderMap, Request, StatusCode},
    Extension,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

const CLIENT: &str = "assertion-client";
const OTHER: &str = "different-key-client";
const BASIC: &str = "basic-client";
const POST: &str = "post-client";
const PUBLIC: &str = "public-client";
const SECRET: &str = "assertion-fixture-secret";
const REDIRECT: &str = "https://client.example.com/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const PEM: &[u8] = include_bytes!("../../../../tests/fixtures/rsa2048-private.pk8.pem");
const PATHS: [&str; 5] = [
    "/token",
    "/device_authorization",
    "/introspect",
    "/revoke",
    "/par",
];

async fn fixture(pool: &sqlx::PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    let grants = vec![
        "authorization_code",
        "refresh_token",
        "client_credentials",
        crate::policy::JWT_BEARER_GRANT_TYPE,
        super::DEVICE_CODE_GRANT_TYPE,
    ];
    register_clients(pool, env, &grants).await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1, token_endpoint_auth_methods_allowed=$2 WHERE environment_id=$3")
        .bind(&grants).bind(vec!["private_key_jwt","client_secret_basic","client_secret_post","none"]).bind(env.environment_id).execute(pool).await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    update_test_policy(&mut state, |p| {
        p.allowed_grant_types = grants.iter().map(|s| (*s).into()).collect();
        p.private_key_jwt_enabled = true;
        p.sender_constraint = crate::management::types::PolicySenderConstraint::None;
        p.require_client_auth_token = false;
        p.require_client_auth_par = false;
        p.require_client_auth_introspection = false;
        p.require_client_auth_revocation = false;
        p.token_exchange = serde_json::from_value(json!({"version":1,"targets":[{"audience":BASIC,"resourceAliases":["https://resource.example/api"]}],"rules":[]})).expect("finite target policy");
        p.client_credentials = serde_json::from_value(json!({"version":1,"resourceServers":[{"targetAudience":BASIC,"introspectionClients":[CLIENT]}],"rules":[{"clientId":CLIENT,"targetAudience":BASIC,"scopes":["api.read"],"defaultScopes":["api.read"],"defaultTarget":true},{"clientId":BASIC,"targetAudience":BASIC,"scopes":["api.read"],"defaultScopes":["api.read"],"defaultTarget":true},{"clientId":POST,"targetAudience":BASIC,"scopes":["api.read"],"defaultScopes":["api.read"],"defaultTarget":true}]})).expect("finite client credentials policy");
    }).await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(env.environment_id);
    use_shared_client_authentication_stores(&mut state, pool, &namespace).await?;
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
    for id in [CLIENT, BASIC, POST, PUBLIC] {
        state
            .protocol
            .par_endpoint
            .register_client(crate::par::Client {
                client_id: id.into(),
                client_secret: None,
                token_endpoint_auth_method: state
                    .clients
                    .try_get(id)?
                    .ok_or("client")?
                    .token_endpoint_auth_method,
                redirect_uris: vec![REDIRECT.into()],
                allowed_scopes: vec!["api.read".into()],
            });
    }
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            state.keys.access_token.clone(),
            crate::authcode::AuthCodeStore::try_from_shared_store_env_with_ttl(
                std::time::Duration::from_secs(300),
                &namespace,
            )?,
            state.tokens.store.as_ref().clone(),
        )
        .with_issuer(state.issuer.to_string()),
    );
    Ok(state)
}

async fn use_shared_client_authentication_stores(
    state: &mut AppState,
    pool: &sqlx::PgPool,
    namespace: &crate::config::RuntimeStateNamespace,
) -> TestResult {
    state.clients = Arc::new(
        crate::client_registry::ClientRegistry::from_shared_store_env_with_runtime_policy(
            crate::client_registry::ClientAssertionRuntimePolicy::try_new(
                std::collections::HashSet::from(["RS256".to_string()]),
                false,
                state.cfg.jwt_runtime().leeway_secs(),
                state.cfg.jose_header_max_len,
                state.cfg.pkjwt_jti_window_secs,
                state.cfg.jwt_bearer_jti_window_secs,
            )?,
            crate::client_registry::JwksRuntimePolicy::default(),
            namespace,
        )?,
    );
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(pool, state.clients.as_ref())
        .await?;
    state.device.code_store = Arc::new(
        crate::device_authz::DeviceCodeStore::try_from_shared_store_env_with_policy(
            state.cfg.device_code_ttl_secs,
            state.cfg.device_code_poll_interval_secs,
            namespace,
        )?,
    );
    state.tokens.store = Arc::new(crate::authcode::TokenStore::try_from_shared_store_env(
        namespace,
    )?);
    state.tokens.validator = Arc::new(crate::authcode::TokenValidator::new(
        state.tokens.store.as_ref().clone(),
        state.keys.access_token.clone(),
    ));
    Ok(())
}

fn claims(state: &AppState, path: &str) -> TestResult<Value> {
    let now = crate::util::now_unix_epoch_secs()?;
    Ok(
        json!({"iss":CLIENT,"sub":CLIENT,"aud":format!("{}{path}",state.issuer),"iat":now,"exp":now+60,"jti":Uuid::new_v4().to_string()}),
    )
}
fn sign(claims: &Value) -> TestResult<String> {
    Ok(jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PEM)?,
    )?)
}
fn fields<'a>(path: &str, jwt: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut pairs = vec![
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", jwt),
    ];
    match path {
        "/token" => pairs.extend([("grant_type", "client_credentials"), ("audience", BASIC)]),
        "/introspect" | "/revoke" => pairs.push(("token", "unknown-token")),
        "/par" => pairs.extend([
            ("client_id", CLIENT),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", "api.read"),
            ("state", "test"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ]),
        _ => pairs.push(("scope", "api.read")),
    }
    pairs
}
async fn send(
    state: &AppState,
    path: &str,
    pairs: &[(&str, &str)],
    auth: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    send_raw(state, path, &serde_urlencoded::to_string(pairs)?, auth).await
}
async fn send_raw(
    state: &AppState,
    path: &str,
    encoded: &str,
    auth: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    let (status, _, body) = send_response(state, path, encoded, auth).await?;
    Ok((status, body))
}
async fn send_response(
    state: &AppState,
    path: &str,
    encoded: &str,
    auth: Option<&str>,
) -> TestResult<(StatusCode, HeaderMap, Value)> {
    let mut req =
        Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(auth) = auth {
        req = req.header(header::AUTHORIZATION, auth);
    }
    let app = super::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let response = app
        .oneshot(req.body(Body::from(encoded.to_owned()))?)
        .await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, headers, value))
}
fn basic() -> String {
    format!("Basic {}", STANDARD.encode(format!("{BASIC}:{SECRET}")))
}
async fn reject(
    state: &AppState,
    path: &str,
    fields: &[(&str, &str)],
    auth: Option<&str>,
) -> TestResult {
    reject_with(
        state,
        path,
        fields,
        auth,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
    )
    .await
}
async fn reject_request(
    state: &AppState,
    path: &str,
    fields: &[(&str, &str)],
    auth: Option<&str>,
) -> TestResult {
    reject_with(
        state,
        path,
        fields,
        auth,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await
}
async fn reject_with(
    state: &AppState,
    path: &str,
    fields: &[(&str, &str)],
    auth: Option<&str>,
    expected_status: StatusCode,
    expected_error: &str,
) -> TestResult {
    let device_count = state.device.code_store.try_active_count()?;
    let par_count = par_count(state)?;
    let (status, headers, body) =
        send_response(state, path, &serde_urlencoded::to_string(fields)?, auth).await?;
    assert_eq!(
        state.device.code_store.try_active_count()?,
        device_count,
        "{path}: {body}"
    );
    assert_eq!(self::par_count(state)?, par_count, "{path}: {body}");
    assert_eq!(status, expected_status, "{path}: {body}");
    assert_eq!(body["error"], expected_error, "{path}: {body}");
    assert_client_challenge(path, &headers, expected_error == "invalid_client")?;
    for field in [
        "access_token",
        "refresh_token",
        "device_code",
        "request_uri",
        "active",
    ] {
        assert!(body.get(field).is_none(), "{body}");
    }
    Ok(())
}

fn assert_client_challenge(path: &str, headers: &HeaderMap, present: bool) -> TestResult {
    let values: Vec<_> = headers.get_all(header::WWW_AUTHENTICATE).iter().collect();
    if present {
        let realm = match path {
            "/introspect" => "token_introspection",
            "/revoke" => "token_revocation",
            _ => "oauth",
        };
        assert_eq!(values.len(), 1, "{path}");
        assert_eq!(
            values[0].to_str()?,
            format!("Basic realm=\"{realm}\", error=\"invalid_client\"")
        );
    } else {
        assert!(values.is_empty(), "{path}");
    }
    Ok(())
}

fn par_count(state: &AppState) -> TestResult<usize> {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let prefix = namespace.redis_atomic_group_prefix(
        crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
        "par",
        "v1",
    );
    let mut conn =
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?.get_connection()?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{prefix}:req:*"))
        .query(&mut conn)?;
    Ok(keys.len())
}

async fn register_clients(
    pool: &sqlx::PgPool,
    env: &TestEnvironment,
    grants: &[&str],
) -> TestResult {
    let key = crate::oidc::OidcSigningKey::from_rsa_pem(
        "assertion-test".into(),
        std::str::from_utf8(PEM)?,
    )?;
    for (id, method) in [
        (CLIENT, "private_key_jwt"),
        (BASIC, "client_secret_basic"),
        (POST, "client_secret_post"),
        (PUBLIC, "none"),
        (OTHER, "private_key_jwt"),
    ] {
        let mut client = sample_registered_client(id);
        client.token_endpoint_auth_method = method.into();
        client.allowed_grant_types = grants.iter().map(|s| (*s).into()).collect();
        client.allowed_scopes = vec!["api.read".into()];
        client.inline_jwks = Some(
            crate::client_registry::RegisteredClientJwks::from_value(
                if id == OTHER {
                    different_jwks()?
                } else {
                    serde_json::to_value(key.jwks())?
                },
                false,
            )
            .map_err(std::io::Error::other)?,
        );
        if id == BASIC || id == POST {
            client.client_secret = Some(SECRET.into());
        }
        crate::dcr_persistence::create_dynamic_registration(
            pool,
            &env.issuer_host,
            &client,
            &["code".into()],
            &Uuid::new_v4().to_string(),
            "assertion-test",
        )
        .await?;
    }
    Ok(())
}

fn different_jwks() -> TestResult<Value> {
    // Public RSA key from the repository's existing standards vector. Only
    // public components are admitted into this client's registration.
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../../../tests/vectors/rfc7520-subset.json"
    ))?;
    let key = &vector["test_cases"][0]["input"]["key"];
    Ok(json!({"keys":[{"kty":"RSA","n":key["n"],"e":key["e"]}]}))
}
