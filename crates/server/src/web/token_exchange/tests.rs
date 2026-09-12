//! Standard token endpoint tests. Authorization is seeded through the issuer;
//! browser consent and application claim release are separate responsibilities.
use crate::policy::{token_exchange::TokenExchangePolicy, TOKEN_EXCHANGE_GRANT_TYPE};
use crate::web::test_support::*;
use crate::web::AppState;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    routing::post,
    Extension, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;

mod legacy_commit;
mod legacy_request;

const CLIENT: &str = "target-exchange-client";
const SECRET: &str = "integration-test-only-client-secret";
const SOURCE_SCOPE: &str = "read write offline_access";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

pub(crate) fn policy(issuer: &str) -> TestResult<TokenExchangePolicy> {
    Ok(serde_json::from_value(json!({"version":1,
        "targets":[{"audience":"internal-api","resourceAliases":["https://api.example/resource"]},{"audience":"closed-api","resourceAliases":[]}],
        "rules":[
            {"clientId":CLIENT,"sourceAudience":format!("{issuer}/userinfo"),"targetAudience":"internal-api",
                "scopes":[{"targetScope":"api.read","sourceScopes":["read"]},{"targetScope":"api.write","sourceScopes":["write"]}],"defaultScopes":["api.read"]},
            {"clientId":CLIENT,"sourceAudience":"internal-api","targetAudience":"internal-api",
                "scopes":[{"targetScope":"api.read","sourceScopes":["api.read"]},{"targetScope":"api.write","sourceScopes":["api.write"]}],"defaultScopes":["api.read"]}]
    }))?)
}

pub(crate) async fn fixture(pool: &PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    let mut client = sample_registered_client(CLIENT);
    client.client_secret = Some(SECRET.into());
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.allowed_scopes = "read write offline_access api.read api.write"
        .split(' ')
        .map(str::to_owned)
        .collect();
    client.allowed_grant_types = vec![
        "authorization_code".into(),
        "refresh_token".into(),
        TOKEN_EXCHANGE_GRANT_TYPE.into(),
    ];
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        "exchange-test-registration-token",
        "exchange-test-registration",
    )
    .await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types = $1, token_endpoint_auth_methods_allowed = $2 WHERE environment_id = $3")
        .bind(&client.allowed_grant_types).bind(vec!["client_secret_basic", "none"]).bind(env.environment_id).execute(pool).await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    let config = Arc::make_mut(&mut state.cfg);
    config.enable_token_exchange = true;
    config.security_policy.sender_constrained = crate::policy::SenderConstraint::None;
    config.token_exchange = policy(&env.issuer_url)?;
    state.keys.access_token = Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?);
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            Arc::clone(&state.keys.access_token),
            crate::authcode::AuthCodeStore::new_process_local_for_tests(),
            state.tokens.store.as_ref().clone(),
        )
        .with_issuer(env.issuer_url.clone())
        .with_token_exchange_policy(config.token_exchange.clone())
        .with_jwt_access_tokens_enabled(true),
    );
    state.tokens.validator = Arc::new(
        crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            Arc::clone(&state.keys.access_token),
            config.security_policy,
        )
        .with_issuer(Some(env.issuer_url.clone()))
        .with_jwt_access_tokens_enabled(true),
    );
    Ok(state)
}

pub(crate) async fn request(
    state: &AppState,
    params: &[(&str, &str)],
    authenticated: bool,
) -> TestResult<(StatusCode, Value)> {
    request_with_proof(state, params, authenticated, None).await
}

async fn request_with_proof(
    state: &AppState,
    params: &[(&str, &str)],
    authenticated: bool,
    proof: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    let app = Router::new()
        .route("/token", post(crate::web::token_endpoint::token))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12453,
        )))))
        .with_state(state.clone());
    let mut builder =
        Request::post("/token").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if authenticated {
        builder = builder.header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{CLIENT}:{SECRET}"))),
        );
    }
    if let Some(proof) = proof {
        builder = builder.header("DPoP", proof);
    }
    let response = app
        .oneshot(builder.body(Body::from(serde_urlencoded::to_string(params)?))?)
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?,
    ))
}

pub(crate) async fn grant(state: &AppState) -> TestResult<Value> {
    grant_with_proof(state, None).await
}

async fn grant_with_proof(state: &AppState, proof: Option<&str>) -> TestResult<Value> {
    let req = serde_json::from_value(json!({"response_type":"code","client_id":CLIENT,
        "redirect_uri":"https://client.example.com/callback","resource":format!("{}/userinfo",state.issuer),
        "scope":SOURCE_SCOPE,"state":uuid::Uuid::new_v4().to_string(),
        "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}))?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(req, "exchange-user".into())?;
    let (status, body) = request_with_proof(
        state,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", CLIENT),
            ("redirect_uri", "https://client.example.com/callback"),
            ("code_verifier", VERIFIER),
        ],
        true,
        proof,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "code issuance: {body}");
    assert!(body["refresh_token"].is_string(), "offline grant expected");
    Ok(body)
}

pub(crate) async fn exchange(
    state: &AppState,
    token: &str,
    extra: &[(&str, &str)],
    authenticated: bool,
) -> TestResult<(StatusCode, Value)> {
    let mut params = vec![
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("client_id", CLIENT),
        ("subject_token", token),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
    ];
    params.extend_from_slice(extra);
    request(state, &params, authenticated).await
}

fn jwt(body: &Value) -> TestResult<Value> {
    let token = body["access_token"].as_str().ok_or("missing token")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(
        token.split('.').nth(1).ok_or("missing payload")?,
    )?)?)
}

async fn scenarios(state: &AppState) -> TestResult {
    let initial = grant(state).await?;
    let source = initial["access_token"].as_str().ok_or("missing source")?;
    let claims = jwt(&initial)?;
    let original = state
        .tokens
        .store
        .try_get_bearer_meta(source)?
        .ok_or("missing source metadata")?;
    let mut corrupt = original.clone();
    corrupt.exchange_grant = None;
    state.tokens.store.try_replace_bearer_meta_record(corrupt)?;
    let same_source = format!("{}/userinfo", state.issuer);
    let (status, body) = exchange(
        state,
        source,
        &[("audience", same_source.as_str()), ("scope", "read")],
        true,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing authority must not downgrade to legacy: {body}"
    );
    assert_eq!(body["error"], "invalid_request");
    let mut altered_expiry = original.clone();
    altered_expiry.expires_at += std::time::Duration::from_secs(600);
    state
        .tokens
        .store
        .try_replace_bearer_meta_record(altered_expiry)?;
    let (status, body) = exchange(state, source, &[("audience", "internal-api")], true).await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "metadata cannot extend the stored subject lifetime: {body}"
    );
    state
        .tokens
        .store
        .try_replace_bearer_meta_record(original)?;

    let (status, denied_target) =
        exchange(state, source, &[("audience", "closed-api")], true).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        denied_target["error"], "invalid_target",
        "unavailable target differs from insufficient scope"
    );
    let (status, first) = exchange(
        state,
        source,
        &[
            ("audience", "internal-api"),
            ("resource", "https://api.example/resource"),
            ("resource", "https://api.example/resource"),
        ],
        true,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "aliases and explicit default: {first}"
    );
    assert_eq!(
        first["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert_eq!(first["token_type"], "Bearer");
    assert_eq!(first["scope"], "api.read");
    let output = jwt(&first)?;
    let proof = signed_dpop_proof()?;
    let (status, bound) = request_with_proof(
        state,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", source),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", "internal-api"),
        ],
        true,
        Some(&proof),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "sender-bound exchange: {bound}");
    assert_eq!(bound["token_type"], "DPoP");
    let jkt = crate::util::compute_dpop_jkt_from_proof_with_max_len(&proof, 8192)
        .ok_or("proof thumbprint missing")?;
    assert_eq!(jwt(&bound)?["cnf"]["jkt"], jkt);
    let bound_token = bound["access_token"].as_str().ok_or("bound output")?;
    let (status, denied) =
        exchange(state, bound_token, &[("audience", "internal-api")], true).await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "sender binding cannot be removed: {denied}"
    );
    assert_eq!(output["aud"], "internal-api");
    assert_eq!(output["sub"], claims["sub"]);
    assert!(output["exp"].as_u64() <= claims["exp"].as_u64());
    assert!(first.get("refresh_token").is_none());
    let token = first["access_token"].as_str().ok_or("missing output")?;
    for selectors in [
        vec![],
        vec![("audience", "unknown")],
        vec![("audience", "internal-api"), ("audience", "unknown")],
        vec![("resource", "https://api.example/resource#f")],
        vec![("audience", "internal-api"), ("scope", "api.admin")],
        vec![("audience", "internal-api"), ("scope", "")],
    ] {
        let (status, body) = exchange(state, source, &selectors, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{selectors:?}: {body}");
        assert!(body.get("access_token").is_none());
    }
    let (status, body) = exchange(state, source, &[("audience", "internal-api")], false).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "client auth is required: {body}"
    );
    let (status, body) = exchange(
        state,
        token,
        &[("audience", "internal-api"), ("scope", "api.write")],
        true,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "exchanged authority cannot regrow: {body}"
    );
    let (status, body) = exchange(
        state,
        token,
        &[("audience", "internal-api"), ("scope", "api.read")],
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "repeat narrowing: {body}");
    let mut restricted = state
        .tokens
        .store
        .try_get_bearer_meta(token)?
        .ok_or("missing same-target subject")?;
    restricted.authorization_details = Some(json!([{"type":"payment","amount":"1"}]));
    state
        .tokens
        .store
        .try_replace_bearer_meta_record(restricted)?;
    let (status, body) = exchange(
        state,
        token,
        &[("audience", "internal-api"), ("scope", "api.read")],
        true,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "same-target RAR must not be erased: {body}"
    );
    let refresh = initial["refresh_token"].as_str().ok_or("missing refresh")?;
    let (status, refreshed) = request(
        state,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT),
            ("refresh_token", refresh),
            ("scope", "read"),
        ],
        true,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "narrowed refresh: {refreshed}");
    let narrower = refreshed["access_token"]
        .as_str()
        .ok_or("missing refreshed token")?;
    let (status, body) = exchange(
        state,
        narrower,
        &[("audience", "internal-api"), ("scope", "api.write")],
        true,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "refresh attenuation: {body}"
    );
    let (status, body) = exchange(state, narrower, &[("audience", "internal-api")], true).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "refresh read remains authorized: {body}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn token_exchange_target_http_contract() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        scenarios(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

fn signed_dpop_proof() -> TestResult<String> {
    use aegaeon_crypto::signing::Ed25519SigningKey;
    let material = Ed25519SigningKey::generate()?;
    signed_dpop_with_key(&material)
}

fn signed_dpop_with_key(material: &aegaeon_crypto::signing::Ed25519KeyData) -> TestResult<String> {
    use aegaeon_crypto::signing::Ed25519SigningKey;
    let key = Ed25519SigningKey::from_pkcs8(&material.pkcs8)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let header = json!({"typ":"dpop+jwt","alg":"EdDSA",
        "jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(&material.public_key)}});
    let claims = json!({"htm":"POST","htu":"http://localhost/token","iat":now,"jti":uuid::Uuid::new_v4().to_string()});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    let proof = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes())?)
    );
    // HTTP unit tests use the middleware mock; independently admit this fixture with the real verifier.
    assert!(ffi::verify_dpop_with_iat_window(
        &proof,
        "POST",
        "http://localhost/token",
        now,
        None,
        300
    )
    .is_some());
    Ok(proof)
}

// Each integration scenario owns an issuer-specific namespace in the private test Redis.
pub(crate) fn use_redis(state: &mut AppState) -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
        "exchange-{}",
        uuid::Uuid::new_v4()
    ));
    let store = crate::authcode::TokenStore::try_from_shared_store_env(&namespace)?;
    let codes = crate::authcode::AuthCodeStore::try_from_shared_store_env_with_ttl(
        std::time::Duration::from_secs(300),
        &namespace,
    )?;
    state.tokens.store = Arc::new(store.clone());
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            Arc::clone(&state.keys.access_token),
            codes,
            store.clone(),
        )
        .with_issuer(state.issuer.to_string())
        .with_token_exchange_policy(state.cfg.token_exchange.clone())
        .with_jwt_access_tokens_enabled(true),
    );
    state.tokens.validator = Arc::new(
        crate::authcode::TokenValidator::with_policy(
            store,
            Arc::clone(&state.keys.access_token),
            state.cfg.security_policy,
        )
        .with_issuer(Some(state.issuer.to_string()))
        .with_jwt_access_tokens_enabled(true),
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn shared_redis_token_exchange_target_http_contract() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        use_redis(&mut state)?;
        scenarios(&state).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

mod lifetime;
mod mtls_profile;
mod rar;
mod sender_flow;
