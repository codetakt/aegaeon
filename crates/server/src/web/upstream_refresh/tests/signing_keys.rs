use super::*;
use crate::web::upstream_metadata::test_support::{HttpFixture, ManualClock};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request},
    routing::get,
    Router,
};
use std::sync::Arc;
use tower::ServiceExt;

mod cases;
mod federation;
mod protected_header;

struct Flow {
    state: AppState,
    request: crate::upstream::UpstreamAuthRequest,
    discovery: crate::oidc::OidcDiscovery,
    new_key: crate::oidc::OidcSigningKey,
    keys: HttpFixture,
    tokens: HttpFixture,
    clock: ManualClock,
}
impl Flow {
    async fn new(f: &Fixture) -> ResultTest<Self> {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .map_err(|_| "fixture RSA generation")?;
        let der = AsDer::<Pkcs8V1Der>::as_der(&key).map_err(|_| "fixture RSA encoding")?;
        let new_key =
            crate::oidc::OidcSigningKey::from_rsa_pkcs8_der("new-key".into(), der.as_ref())?;
        let keys = HttpFixture::new(serde_json::to_string(&new_key.jwks())?).await?;
        let tokens = HttpFixture::new("{}".into()).await?;
        let mut discovery = f.discovery.clone();
        discovery.id_token_signing_alg_values_supported = vec!["RS256".into()];
        discovery.jwks_uri = format!("{}/tenant/keys", keys.url);
        discovery.token_endpoint = format!("{}/tenant/token", tokens.url);
        discovery.authorization_endpoint = format!("{}/tenant/authorize", tokens.url);
        discovery.token_endpoint_auth_methods_supported = Some(vec!["none".into()]);
        let mut request = f.request.clone();
        request.jwks_uri = discovery.jwks_uri.clone();
        request.token_endpoint = discovery.token_endpoint.clone();
        let mut state = f.state.clone();
        let clock = ManualClock::new();
        state.upstream.jwks_fetches = Arc::new(clock.coordinator());
        state
            .upstream
            .discovery_cache
            .try_insert(&request.issuer, discovery.clone())?;
        state.upstream.jwks_cache.try_insert(
            &discovery.jwks_uri,
            aegaeon_jose::jwk::JwkSet::from_value(serde_json::to_value(f.signing_key.jwks())?)?,
        )?;
        Ok(Self {
            state,
            request,
            discovery,
            new_key,
            keys,
            tokens,
            clock,
        })
    }
    fn signed(&self, claims: &Value) -> ResultTest<String> {
        Ok(jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: jsonwebtoken::Algorithm::RS256,
                kid: Some(self.new_key.kid().into()),
                ..Default::default()
            },
            claims,
            self.new_key.local_encoding_key().ok_or("fixture key")?,
        )?)
    }
    fn token(&self, token: String) {
        self.tokens.respond(StatusCode::OK,json!({"id_token":token,"access_token":"private-access-token","refresh_token":"private-refresh-rotated","token_type":"Bearer","expires_in":3600}).to_string());
    }
    async fn callback(&self) -> ResultTest<Response> {
        let mut request = self.request.clone();
        request.state = Uuid::new_v4().to_string();
        request.redirect_uri =
            crate::web::build_upstream_redirect_uri(&self.state.base_url, "refresh-test");
        let secret = crate::upstream::random_token(32);
        request.browser_binding_digest = Some(aegaeon_crypto::hash::sha256_hex(secret.as_bytes()));
        let cookie = format!(
            "{}={secret}",
            crate::web::upstream_browser_binding::cookie_name(&request.state)
        );
        let query = serde_urlencoded::to_string([
            ("state", request.state.as_str()),
            ("code", "code"),
            ("iss", request.issuer.as_str()),
        ])?;
        self.state.upstream.auth_store.try_insert(request)?;
        let app = Router::new()
            .route(
                "/oauth/upstream/:connection/callback",
                get(crate::web::upstream_callback::upstream_callback),
            )
            .with_state(self.state.clone());
        Ok(app
            .oneshot(
                Request::builder()
                    .uri(format!("/oauth/upstream/refresh-test/callback?{query}"))
                    .header(header::COOKIE, cookie)
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        12345,
                    ))))
                    .body(Body::empty())?,
            )
            .await?)
    }
    async fn refresh(&self, f: &Fixture) -> Result<Response, Response> {
        let link = f.load().await?;
        let mut profile = upstream_tests::base_profile();
        profile.allowed_grant_types.push("refresh_token".into());
        validate_upstream_refresh_profile_policy(
            &profile,
            &f.env.issuer_url,
            &link.upstream_auth_method,
        )?;
        let exchange =
            perform_upstream_refresh_exchange(&self.state, &f.env.issuer_url, &link, &profile)
                .await?;
        validate_upstream_refresh_exchange(&self.state, &f.env.issuer_url, &link, &exchange)
            .await?;
        persist_upstream_refresh_exchange(
            &f.pool,
            &link,
            &exchange.token_response,
            &f.env.issuer_url,
        )
        .await?;
        Ok(build_upstream_refresh_response(
            &link,
            &exchange.token_response,
        ))
    }
    async fn assert_no_effects(
        &self,
        f: &Fixture,
        stored: &(Vec<u8>, i64),
        sessions: usize,
    ) -> ResultTest {
        assert_eq!(&f.stored().await?, stored);
        assert_eq!(
            self.state
                .browser_auth
                .auth_sessions
                .try_list_for_user(&f.user)?
                .len(),
            sessions
        );
        let links: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.account_links WHERE environment_id=$1",
        )
        .bind(f.env.environment_id)
        .fetch_one(&f.pool)
        .await?;
        let users: i64 =
            sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1")
                .bind(f.env.environment_id)
                .fetch_one(&f.pool)
                .await?;
        assert_eq!((links, users), (1, 1));
        Ok(())
    }
    fn cache_keys(&self, value: Value) -> ResultTest {
        self.state.upstream.jwks_cache.try_insert(
            &self.discovery.jwks_uri,
            aegaeon_jose::jwk::JwkSet::from_value(value)?,
        )?;
        Ok(())
    }
}
