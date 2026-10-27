use crate::web::{
    auth_session::{AuthSessionTimes, UpstreamLogoutSession},
    test_support::*,
    AppState, AUTH_SESSION_COOKIE_NAME,
};
use crate::{
    management::types::PolicyDocument,
    oidc::{OidcSessionContext, OidcSessionStore},
};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Extension,
};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower::ServiceExt;
pub(super) const CLIENT: &str = "logout-client";
pub(super) const REDIRECT: &str = "https://rp.example/signed-out";

pub(super) struct Fixture {
    pub state: AppState,
    pub relay_prefix: String,
}
pub(super) struct Session {
    pub id: String,
    pub oidc: String,
}
pub(super) struct Page {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}
pub(super) struct Transaction {
    pub token: String,
    pub cookie: String,
    pub location: String,
}

impl Fixture {
    pub async fn new(pool: &PgPool, env: &TestEnvironment) -> TestResult<Self> {
        for id in [CLIENT, "other-client"] {
            let mut client = sample_registered_client(id);
            client.post_logout_redirect_uris = vec![REDIRECT.into()];
            crate::dcr_persistence::create_dynamic_registration(
                pool,
                &env.issuer_host,
                &client,
                &["code".into()],
                &format!("logout-registration-{id}"),
                "logout-test",
            )
            .await?;
        }
        let policy = PolicyDocument {
            oidc_enabled: true,
            oidc_enable_logout: true,
            id_token_time_to_live_seconds: 300,
            ..PolicyDocument::default()
        };
        seed_oidc_configuration(pool, env, policy.clone(), "logout-confirmation").await?;
        let mut state = test_app_state(pool.clone(), env).await?;
        let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
            "logout-{}",
            uuid::Uuid::new_v4()
        ));
        state.browser_auth.auth_sessions = Arc::new(
            crate::web::AuthSessionStore::try_from_management_policy(&policy, &namespace)?,
        );
        state.oidc.sessions =
            Some(OidcSessionStore::try_new_from_shared_store_env_with_ttl_secs(600, &namespace)?);
        state.device.local_login_rate_limiter = Arc::new(
            crate::device_authz::VerificationRateLimiter::try_from_shared_store_env(
                "AEGAEON_TEST_REDIS_URL",
                "logout-confirmation",
                &namespace,
            )?,
        );
        let relay_prefix = format!("logout-confirmation-relay:{}", uuid::Uuid::new_v4());
        state.upstream.logout_relay_store =
            Arc::new(crate::web::UpstreamLogoutRelayStore::redis_for_test(
                &std::env::var("AEGAEON_TEST_REDIS_URL")?,
                &relay_prefix,
                Duration::from_secs(300),
            )?);
        Ok(Self {
            state,
            relay_prefix,
        })
    }
    pub async fn session(
        &self,
        user: &str,
        upstream: Option<UpstreamLogoutSession>,
    ) -> TestResult<Session> {
        let now = crate::util::now_unix_epoch_secs()?;
        let id = self
            .state
            .browser_auth
            .auth_sessions
            .try_create_async(
                user.into(),
                AuthSessionTimes::local(now),
                None,
                None,
                upstream,
            )
            .await?
            .ok_or("session capacity")?;
        let sessions = self.state.oidc.sessions.as_ref().ok_or("OIDC store")?;
        let oidc = sessions.try_get_or_create_session(OidcSessionContext {
            user_id: user,
            auth_session_id: &id,
        })?;
        assert!(sessions.try_add_client(&oidc, CLIENT)?);
        assert!(sessions.try_add_client(&oidc, "associated-rp")?);
        Ok(Session { id, oidc })
    }
    pub fn hint(&self, user: &str, sid: Option<&str>) -> TestResult<String> {
        let now = crate::util::now_unix_epoch_secs_i64()?;
        let claims = serde_json::json!({"iss":self.state.issuer.as_str(),"sub":user,"aud":CLIENT,"iat":now,"exp":now+300,"sid":sid});
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("logout-confirmation".into());
        let pem = include_bytes!("../../../../tests/fixtures/rsa2048-private.pk8.pem");
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(pem)?,
        )?;
        // This invokes the production signature/own-issuer/time checks.
        crate::web::logout_id_token_hint::decode_id_token_hint(
            self.state.oidc.config.as_ref().ok_or("config")?,
            &token,
            self.state.cfg.jose_header_max_len,
        )
        .map_err(|e| e.public_description().to_string())?;
        Ok(token)
    }
    pub async fn intact(&self, session: &Session) -> TestResult {
        assert!(self
            .state
            .browser_auth
            .auth_sessions
            .try_get_async(session.id.clone())
            .await?
            .is_some());
        assert!(self
            .state
            .oidc
            .sessions
            .as_ref()
            .ok_or("sessions")?
            .try_add_client(&session.oidc, "still-active")?);
        Ok(())
    }
    pub async fn ended(&self, session: &Session) -> TestResult {
        assert!(self
            .state
            .browser_auth
            .auth_sessions
            .try_get_async(session.id.clone())
            .await?
            .is_none());
        let sessions = self.state.oidc.sessions.as_ref().ok_or("sessions")?;
        assert!(!sessions.try_add_client(&session.oidc, "must-not-attach")?);
        let event = sessions
            .try_logout_by_sid(&session.oidc)?
            .ok_or("idempotent event")?;
        assert!(event.client_ids.iter().any(|c| c == CLIENT));
        assert!(event.client_ids.iter().any(|c| c == "associated-rp"));
        Ok(())
    }
    pub async fn start(
        &self,
        method: Method,
        fields: &[(&str, &str)],
        sid: Option<&str>,
    ) -> TestResult<Transaction> {
        let encoded = serde_urlencoded::to_string(fields)?;
        let (uri, body) = if method == Method::POST {
            ("/logout".to_string(), encoded)
        } else {
            (format!("/logout?{encoded}"), String::new())
        };
        let cookie = sid.map(|sid| format!("{AUTH_SESSION_COOKIE_NAME}={sid}"));
        let response = send(&self.state, method, &uri, cookie.as_deref(), None, &body).await?;
        assert_eq!(response.status, StatusCode::SEE_OTHER, "{}", response.body);
        let location = response.headers[header::LOCATION].to_str()?.to_string();
        assert!(location.starts_with("/logout/confirm?transaction="));
        let token = location.split_once('=').ok_or("token")?.1.to_string();
        let set = response.headers[header::SET_COOKIE].to_str()?;
        for flag in [
            "__Host-",
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=300",
        ] {
            assert!(set.contains(flag));
        }
        assert!(!set.contains("Domain="));
        let cookie = set.split(';').next().ok_or("cookie")?.to_string();
        Ok(Transaction {
            token,
            cookie,
            location,
        })
    }
}
impl Transaction {
    pub fn cookies(&self, sid: Option<&str>) -> String {
        sid.map_or_else(
            || self.cookie.clone(),
            |id| format!("{}; {AUTH_SESSION_COOKIE_NAME}={id}", self.cookie),
        )
    }
    pub async fn show(&self, state: &AppState, sid: Option<&str>) -> TestResult<Page> {
        send(
            state,
            Method::GET,
            &self.location,
            Some(&self.cookies(sid)),
            None,
            "",
        )
        .await
    }
    pub async fn choose(
        &self,
        state: &AppState,
        sid: Option<&str>,
        choice: &str,
    ) -> TestResult<Page> {
        send(
            state,
            Method::POST,
            "/logout/confirm",
            Some(&self.cookies(sid)),
            Some(state.issuer.as_str()),
            &serde_urlencoded::to_string([
                ("transaction", self.token.as_str()),
                ("decision", choice),
            ])?,
        )
        .await
    }
}
pub(super) async fn send(
    state: &AppState,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
    body: &str,
) -> TestResult<Page> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        req = req.header(header::ORIGIN, origin);
    }
    send_request(state, req.body(Body::from(body.to_string()))?).await
}

pub(super) async fn send_request(state: &AppState, request: Request<Body>) -> TestResult<Page> {
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 43210)),
    )));
    let response = app.oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    // Runtime-authority admission can return a generic 503 before the logout
    // handler; its header policy is outside this fixture's logout-page check.
    if status != StatusCode::SERVICE_UNAVAILABLE {
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
    let body = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
    Ok(Page {
        status,
        headers,
        body,
    })
}
