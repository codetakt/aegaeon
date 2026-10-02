//! Authenticated HTTP handlers, real grant commits, isolated Redis and PostgreSQL.
use super::*;
use crate::authcode::types::{
    BearerTokenMeta, BearerTokenMetaInput, CnfClaim, RefreshToken, RefreshTokenInput, SenderBinding,
};
use crate::config::{RuntimeRedisAtomicGroup, RuntimeStateNamespace};
use crate::management::types::{PolicyDocument, PolicySenderConstraint};
use crate::metrics_integration::MetricsIntegration;
use crate::web::test_support::*;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request},
    middleware,
    routing::{get, post},
    Extension, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use redis::Commands;
use serde_json::Value;
use sqlx::PgPool;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tower::ServiceExt;

mod authentication;
mod cases;
mod failures;
mod grant_family;
mod schema;
mod signed_recipient;
mod stored_jwt;
mod subject;

const OWNER: &str = "grant-owner";
const OTHER: &str = "unrelated-client";
const SECRET: &str = "public-local-fixture-secret";

struct Fixture {
    state: AppState,
    pool: PgPool,
    env: TestEnvironment,
    prefix: String,
    redis_url: String,
    namespace: RuntimeStateNamespace,
}

impl Fixture {
    async fn new(retain: bool) -> TestResult<Self> {
        let pool = test_pg_pool()
            .await?
            .ok_or("AEGAEON_DATABASE_URL required")?;
        let env = setup_test_environment(&pool).await?;
        let resource = crate::resource_audience::protected_resource(&env.issuer_url);
        for id in [OWNER, OTHER, resource.as_str()] {
            let mut client = sample_registered_client(id);
            client.client_secret = Some(SECRET.into());
            client.token_endpoint_auth_method = if id == resource {
                "client_secret_post"
            } else {
                "client_secret_basic"
            }
            .into();
            crate::dcr_persistence::create_dynamic_registration(
                &pool,
                &env.issuer_host,
                &client,
                &["code".into()],
                &uuid::Uuid::new_v4().to_string(),
                "introspection-parent-fixture",
            )
            .await?;
        }
        let policy = PolicyDocument {
            sender_constraint: PolicySenderConstraint::None,
            retain_refresh_chain: retain,
            jwt_introspection_enabled: true,
            ..PolicyDocument::default()
        };
        sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=jsonb_set(configuration_document,'{policy}',$1) WHERE environment_id=$2 AND status='ACTIVE'")
            .bind(serde_json::to_value(&policy)?).bind(env.environment_id).execute(&pool).await?;
        sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=$1 WHERE environment_id=$2")
            .bind(vec!["client_secret_basic", "client_secret_post"]).bind(env.environment_id).execute(&pool).await?;
        let mut state = test_app_state(pool.clone(), &env).await?;
        let namespace = RuntimeStateNamespace::for_tests(format!(
            "introspection-parent-{}",
            uuid::Uuid::new_v4()
        ));
        let prefix = namespace.redis_atomic_group_prefix(
            RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
            "token-store",
            "v3",
        );
        state.tokens.store = Arc::new(crate::authcode::TokenStore::try_from_shared_store_env(
            &namespace,
        )?);
        state.tokens.validator = Arc::new(crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            state.keys.access_token.clone(),
            state.cfg.security_policy,
        ));
        state.keys.jwt_introspection =
            Some(Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?));
        let metrics = Arc::new(MetricsIntegration::new(Arc::new(
            aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?,
        )));
        MetricsIntegration::register_global(&metrics);
        let redis_url = std::env::var("AEGAEON_TOKEN_STORE_REDIS_URL")?;
        Ok(Self {
            state,
            pool,
            env,
            prefix,
            redis_url,
            namespace,
        })
    }

    fn connection(&self) -> TestResult<redis::Connection> {
        Ok(redis::Client::open(self.redis_url.as_str())?.get_connection()?)
    }

    fn key(&self, kind: &str, token: &str) -> String {
        // Match the private v3 key layout solely to inject isolated storage faults.
        let mut digest = aegaeon_crypto::hash::Sha256Hasher::new();
        digest.update(b"aegaeon:token-store:v3");
        digest.update(&(token.len() as u64).to_be_bytes());
        digest.update(token.as_bytes());
        format!(
            "{}:{kind}:{}",
            self.prefix,
            URL_SAFE_NO_PAD.encode(digest.finalize())
        )
    }

    async fn finish(self, result: TestResult) -> TestResult {
        let cleanup_redis = (|| -> TestResult {
            let mut conn = self.connection()?;
            let keys: Vec<String> = conn.scan_match(format!("{}:*", self.prefix))?.collect();
            if !keys.is_empty() {
                let _: usize = conn.del(keys)?;
            }
            Ok(())
        })();
        let cleanup_pg = cleanup_test_environment(&self.pool, &self.env).await;
        finish_test(result.and(cleanup_redis), cleanup_pg)
    }
}

fn grant(
    state: &AppState,
    parent: bool,
    binding: Option<SenderBinding>,
) -> (AccessToken, Option<RefreshToken>, BearerTokenMeta) {
    let mut access = AccessToken::new(OWNER.into(), "subject".into(), Some("read".into()), 300);
    access.cnf = binding.as_ref().map(|binding| match binding {
        SenderBinding::DPoP { jkt } => CnfClaim::Jkt(jkt.clone()),
        SenderBinding::Mtls { fingerprint } => CnfClaim::X5tS256(
            crate::middleware::tls::mtls_fingerprint_to_x5t_s256(fingerprint)
                .expect("fixture fingerprint"),
        ),
    });
    access.token_type = AccessToken::type_for_confirmation(access.cnf.as_ref()).into();
    let audience = crate::resource_audience::protected_resource(state.issuer.as_str());
    let refresh = parent.then(|| {
        let mut token = RefreshToken::with_ttl(
            RefreshTokenInput {
                scope: Some("read".into()),
                resource: Some(audience.clone()),
                ..RefreshTokenInput::new(OWNER.into(), "subject".into())
            },
            600,
        );
        token.sender_binding.clone_from(&binding);
        token
    });
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: OWNER.into(),
        user_id: "subject".into(),
        granted_scopes: vec!["read".into()],
        audience,
        sender_binding: binding,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access.created_at + Duration::from_secs(300),
        refresh_parent: refresh.as_ref().map(|r| r.token.clone()),
    });
    (access, refresh, meta)
}

fn router(state: &AppState) -> Router {
    Router::new()
        .route("/introspect", post(introspect))
        .route("/revoke", post(revoke))
        .route("/resource", get(crate::web::resource_endpoint::resource))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::web::runtime_authority_guard::runtime_authority_guard_middleware,
        ))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12458,
        )))))
        .with_state(state.clone())
}

async fn introspection(
    state: &AppState,
    token: &str,
    caller: &str,
    jwt: bool,
) -> TestResult<(StatusCode, Value)> {
    let mut request = Request::post("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    let mut fields = vec![("token", token)];
    if caller == crate::resource_audience::protected_resource(state.issuer.as_str()) {
        // URI client IDs use the registered post method; Basic parsing is a sibling concern.
        fields.extend([("client_id", caller), ("client_secret", SECRET)]);
    } else {
        request = request.header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{caller}:{SECRET}"))),
        );
    }
    if jwt {
        request = request.header(header::ACCEPT, "application/token-introspection+jwt");
    }
    let response = router(state)
        .oneshot(request.body(Body::from(serde_urlencoded::to_string(fields)?))?)
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    if status == StatusCode::OK {
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            if jwt && state.cfg.jwt_runtime().introspection_enabled() {
                "application/token-introspection+jwt"
            } else {
                "application/json"
            }
        );
    }
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let body = if jwt && state.cfg.jwt_runtime().introspection_enabled() && status == StatusCode::OK
    {
        verify_response(state, std::str::from_utf8(&bytes)?, caller)?
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body))
}

fn verify_response(state: &AppState, jwt: &str, caller: &str) -> TestResult<Value> {
    let parts: Vec<_> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let input = format!("{}.{}", parts[0], parts[1]);
    let key = state.keys.jwt_introspection.as_ref().ok_or("key missing")?;
    let jwk = key.jwt_signing_public_jwk().ok_or("public key missing")?;
    let public = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().ok_or("x missing")?)?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    aegaeon_crypto::signature::verify_ed25519(&public, input.as_bytes(), &signature)?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "token-introspection+jwt");
    let payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    assert_eq!(payload["iss"], state.issuer.as_str());
    assert_eq!(payload["aud"], caller);
    Ok(payload["token_introspection"].clone())
}

// Existing state/signature regression cases use a genuine recipient for signed responses.
// Owner-only versus resource-reader disclosure is checked explicitly in signed_recipient.
fn reader(state: &AppState, jwt: bool) -> String {
    if jwt {
        crate::resource_audience::protected_resource(state.issuer.as_str())
    } else {
        OWNER.into()
    }
}

async fn observe(state: &AppState, token: &str, active: bool) -> TestResult {
    let resource = router(state)
        .oneshot(
            Request::get("/resource")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        resource.status(),
        if active {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        }
    );
    for jwt in [false, true] {
        let (status, body) = introspection(state, token, &reader(state, jwt), jwt).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["active"], active);
        if !active {
            assert_eq!(body, json!({"active":false}));
        }
    }
    Ok(())
}
