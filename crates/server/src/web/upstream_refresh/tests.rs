//! Actual PostgreSQL callback/load/rotation paths with signed upstream ID Tokens.
use super::*;
use crate::web::upstream_callback_exchange::UpstreamCallbackExchange;
use crate::web::upstream_callback_users::persist_upstream_callback_refresh_token;
use crate::web::upstream_id_token::{decode_upstream_id_token, UpstreamIdTokenDecodeInput};
use crate::web::upstream_refresh_links::fixture_upstream_refresh_caller;
use crate::web::upstream_refresh_token_envelope::open_upstream_refresh_token;
use crate::web::{test_support::*, upstream_tests};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::{error::Error, time::Duration};
use uuid::Uuid;

type ResultTest<T = ()> = Result<T, Box<dyn Error>>;
mod cases;
mod configuration_currentness;
mod currentness;
mod freshness;
mod last_use;
mod policy_currentness;
mod signing_keys;

struct Fixture {
    pool: PgPool,
    env: TestEnvironment,
    state: AppState,
    request: crate::upstream::UpstreamAuthRequest,
    discovery: crate::oidc::OidcDiscovery,
    signing_key: crate::oidc::OidcSigningKey,
    subject_hash: String,
    user: String,
    caller: String,
    profile: crate::oauth_profile::ResolvedProfile,
    link_id: Uuid,
}

impl Fixture {
    async fn new() -> ResultTest<Self> {
        let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
        let env = setup_test_environment(&pool).await?;
        let version: Uuid = sqlx::query_scalar(
            "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        sqlx::query("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,sender_constrained,allowed_grant_types,token_endpoint_auth_methods_allowed) VALUES($1,$2,'refresh-policy','UPSTREAM',true,'NONE',ARRAY['authorization_code','refresh_token'],ARRAY['none'])")
            .bind(env.environment_id).bind(version).execute(&pool).await?;
        let conn:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) VALUES($1,$2,'refresh-test','refresh-test','https://issuer.example','client','none','ACTIVE') RETURNING id").bind(env.environment_id).bind(version).fetch_one(&pool).await?;
        let caller = format!("caller-{}", Uuid::new_v4());
        crate::dcr_persistence::create_dynamic_registration(
            &pool,
            &env.issuer_host,
            &sample_registered_client(&caller),
            &["code".into()],
            &Uuid::new_v4().to_string(),
            "refresh-fixture",
        )
        .await?;
        let user = format!("local-{}", Uuid::new_v4());
        let user_id:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES($1,$2,'ACTIVE') RETURNING id").bind(env.environment_id).bind(&user).fetch_one(&pool).await?;
        let subject_hash = crate::upstream::upstream_subject_link_hash(
            "https://issuer.example",
            "private-subject",
        );
        let link_id=sqlx::query_scalar("INSERT INTO aegaeon.account_links(environment_id,connection_id,upstream_issuer,upstream_sub_hash,end_user_id) VALUES($1,$2,'https://issuer.example',$3,$4) RETURNING id").bind(env.environment_id).bind(conn).bind(&subject_hash).bind(user_id).fetch_one(&pool).await?;
        let state = test_app_state(pool.clone(), &env).await?;
        let mut request =
            upstream_tests::make_auth_request("refresh-context", Duration::from_secs(60));
        request.context = crate::upstream::UpstreamConnectionContext::new(
            conn,
            env.team_id,
            env.tenant_id,
            env.environment_id,
            version,
        );
        let mut discovery = upstream_tests::base_discovery(&request.issuer)?;
        // Cached keys still undergo current outbound URL admission.
        discovery.jwks_uri = "http://127.0.0.1:9/jwks".into();
        let signing_key = crate::oidc::OidcSigningKey::from_rsa_pem(
            "refresh-context".into(),
            include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem"),
        )?;
        let jwks =
            aegaeon_jose::jwk::JwkSet::from_value(serde_json::to_value(signing_key.jwks())?)?;
        state
            .upstream
            .jwks_cache
            .try_insert(&discovery.jwks_uri, jwks)?;
        let profile =
            crate::oauth_profile::resolve_upstream_profile(&pool, &env.issuer_url, "refresh-test")
                .await
                .map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            pool,
            env,
            state,
            request,
            discovery,
            signing_key,
            subject_hash,
            user,
            caller,
            profile,
            link_id,
        })
    }

    fn claims(&self) -> ResultTest<Value> {
        let now = crate::web::now_epoch_secs()?;
        // Refresh preserves the original authentication time even when key
        // generation or HTTP/DB work crosses a wall-clock second boundary.
        let auth_time = self
            .request
            .issued_at
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .saturating_sub(60);
        Ok(
            json!({"iss":self.request.issuer,"sub":"private-subject","aud":"client","iat":now,"exp":now+3600,"auth_time":auth_time,"nonce":"nonce"}),
        )
    }
    fn signed(&self, claims: &Value) -> ResultTest<String> {
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(self.signing_key.kid().into()),
            ..Default::default()
        };
        Ok(jsonwebtoken::encode(
            &header,
            claims,
            self.signing_key
                .local_encoding_key()
                .ok_or("local signing key")?,
        )?)
    }
    fn callback(
        &self,
        claims: &Value,
        refresh: Option<&str>,
    ) -> ResultTest<UpstreamCallbackExchange> {
        self.callback_with_request(claims, refresh, &self.request)
    }
    fn callback_with_request(
        &self,
        claims: &Value,
        refresh: Option<&str>,
        request: &crate::upstream::UpstreamAuthRequest,
    ) -> ResultTest<UpstreamCallbackExchange> {
        let raw = self.signed(claims)?;
        let jwks = self
            .state
            .upstream
            .jwks_cache
            .try_get(&self.discovery.jwks_uri)?
            .ok_or("fixture jwks")?;
        let id_token = decode_upstream_id_token(UpstreamIdTokenDecodeInput {
            token: &raw,
            jwks: &jwks,
            discovery: &self.discovery,
            request,
            access_token: Some("access-token"),
            code: "code",
            jwt_leeway_secs: 60,
            jose_header_max_len: self.state.cfg.jose_header_max_len,
        })
        .map_err(|e| e.message)?;
        Ok(UpstreamCallbackExchange {
            discovery: self.discovery.clone(),
            token_response: Self::response(Some(raw), refresh),
            id_token,
            upstream_sub_hash: self.subject_hash.clone(),
        })
    }
    fn response(id_token: Option<String>, refresh: Option<&str>) -> UpstreamTokenResponse {
        UpstreamTokenResponse {
            id_token,
            access_token: Some("private-access-token".into()),
            token_type: Some("Bearer".into()),
            expires_in: Some(3600),
            refresh_token: refresh.map(str::to_string),
        }
    }
    async fn store_callback(&self, exchange: &UpstreamCallbackExchange) -> Result<(), Response> {
        let mut tx = self.pool.begin().await.map_err(|_| {
            json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
                &self.env.issuer_url,
            )
        })?;
        persist_upstream_callback_refresh_token(
            &mut tx,
            &self.request,
            exchange,
            &self.env.issuer_url,
        )
        .await?;
        tx.commit().await.map_err(|_| {
            json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
                &self.env.issuer_url,
            )
        })
    }
    async fn load(&self) -> Result<UpstreamRefreshLink, Response> {
        load_upstream_refresh_link(
            &self.pool,
            &fixture_upstream_refresh_caller(self.user.clone(), self.caller.clone()),
            Some(&self.request.issuer),
            &self.env.issuer_url,
        )
        .await
    }
    async fn stored(&self) -> ResultTest<(Vec<u8>, i64)> {
        let row=sqlx::query("SELECT upstream_refresh_token_encrypted,upstream_refresh_token_generation FROM aegaeon.account_links WHERE id=$1").bind(self.link_id).fetch_one(&self.pool).await?;
        Ok((row.try_get(0)?, row.try_get(1)?))
    }
    async fn refresh(
        &self,
        link: &UpstreamRefreshLink,
        claims: Option<&Value>,
        refresh: Option<&str>,
    ) -> Result<Response, Response> {
        let id_token = claims.map(|c| self.signed(c)).transpose().map_err(|_| {
            json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
                &self.env.issuer_url,
            )
        })?;
        let exchange = UpstreamRefreshExchange {
            request_started_at: crate::web::now_epoch_secs().map_err(|_| {
                json_error_with_iss(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    None,
                    &self.env.issuer_url,
                )
            })?,
            client: reqwest::Client::new(),
            discovery: self.discovery.clone(),
            token_response: Self::response(id_token, refresh),
        };
        validate_upstream_refresh_exchange(&self.state, &self.env.issuer_url, link, &exchange)
            .await?;
        persist_upstream_refresh_exchange(
            &self.pool,
            link,
            &exchange.token_response,
            &self.profile,
            &self.env.issuer_url,
        )
        .await?;
        Ok(build_upstream_refresh_response(
            link,
            &exchange.token_response,
        ))
    }
    async fn cleanup(&self) -> ResultTest {
        sqlx::query("DELETE FROM aegaeon.account_links WHERE environment_id=$1")
            .bind(self.env.environment_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM aegaeon.connections WHERE environment_id=$1")
            .bind(self.env.environment_id)
            .execute(&self.pool)
            .await?;
        cleanup_test_environment(&self.pool, &self.env).await?;
        Ok(())
    }
}

struct KeyGuard(Option<std::ffi::OsString>);
impl Drop for KeyGuard {
    fn drop(&mut self) {
        if let Some(v) = &self.0 {
            std::env::set_var(crate::key_encryption::KEY_ENCRYPTION_KEY_ENV, v);
        } else {
            std::env::remove_var(crate::key_encryption::KEY_ENCRYPTION_KEY_ENV);
        }
    }
}
fn run(
    expect_warning: bool,
    scenario: impl FnOnce(&tokio::runtime::Runtime, &Fixture) -> ResultTest,
) -> ResultTest {
    let runtime = tokio::runtime::Runtime::new()?;
    let fixture = runtime.block_on(Fixture::new())?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key lock")?;
    let _key = KeyGuard(std::env::var_os(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
    ));
    std::env::set_var(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        URL_SAFE_NO_PAD.encode([0x51; 32]),
    );
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .without_time()
        .with_writer(move || CapturedWarnings(writer.clone()))
        .finish();
    let result = tracing::subscriber::with_default(subscriber, || scenario(&runtime, &fixture));
    let log = String::from_utf8(captured.lock().map_err(|_| "log lock")?.clone())?;
    if expect_warning {
        assert!(log.contains("upstream refreshed id_token validation failed"));
    }
    for secret in [
        "private-subject",
        "private-refresh",
        "private-access-token",
        "changed-private-nonce",
    ] {
        assert!(!log.contains(secret), "sensitive value reached warning log");
    }
    let cleanup = runtime.block_on(fixture.cleanup());
    result?;
    cleanup
}
fn error(response: Response) -> String {
    format!("fixture response {}", response.status())
}

#[derive(Clone)]
struct CapturedWarnings(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for CapturedWarnings {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log lock"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
