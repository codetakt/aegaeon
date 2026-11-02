use super::super::delivery::{dispatch_at, Clock};
use super::*;
use crate::oidc::session::delivery::{
    Binding, Candidate, Command, Completion, Identity, Outcome, Permit, Request,
};
use crate::oidc::OidcSessionStore;
use std::sync::Mutex;

mod http;
mod protocol;
mod redis;

const NOW: u64 = 1_700_000_000;

struct SessionFixture {
    a: OidcSessionStore,
    b: OidcSessionStore,
    event: OidcLogoutEvent,
    redis: Option<(String, String)>,
}

impl SessionFixture {
    fn local(ttl: u64) -> TestResult<Self> {
        let a = OidcSessionStore::new_process_local_with_ttl_for_tests(ttl);
        Self::create(a.clone(), a, None)
    }
    fn redis(ttl: u64) -> TestResult<Self> {
        let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
        let prefix = format!(
            "logout-delivery-test:{{{}}}",
            aegaeon_crypto::rand::random_base64url(16)
        );
        let a =
            OidcSessionStore::new_redis_for_test(&url, &prefix, ttl).map_err(anyhow::Error::msg)?;
        let b =
            OidcSessionStore::new_redis_for_test(&url, &prefix, ttl).map_err(anyhow::Error::msg)?;
        Self::create(a, b, Some((url, prefix)))
    }
    fn create(
        a: OidcSessionStore,
        b: OidcSessionStore,
        redis: Option<(String, String)>,
    ) -> TestResult<Self> {
        let sid = a.get_or_create_session("subject", "browser");
        a.add_client(&sid, "a");
        a.add_client(&sid, "b");
        let event = a
            .try_logout_by_sid_at(&sid, NOW)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("event"))?;
        Ok(Self { a, b, event, redis })
    }
    fn request(&self, client: &str, command: Command, now: u64) -> Request {
        let mut request = Request::new(
            Identity {
                sid: self.event.sid.clone(),
                event_jti: self.event.jti.clone(),
                subject: self.event.user_id.clone(),
                client_id: client.to_string(),
            },
            Some(Binding {
                issuer: ISSUER.to_string(),
                uri: "https://rp.example/logout".to_string(),
                session_required: false,
            }),
            command,
        );
        request.test_now = Some(now);
        request
    }
    fn candidate(&self, client: &str, now: u64) -> TestResult<Candidate> {
        let cfg = config(local_key()?);
        let jti = aegaeon_crypto::rand::random_base64url(32);
        let claims = build_backchannel_logout_claims_at(
            &cfg,
            client,
            &self.event.sid,
            Some("subject"),
            &jti,
            UNIX_EPOCH + Duration::from_secs(now),
        )
        .map_err(anyhow::Error::msg)?;
        Ok(Candidate::new(
            cfg.signing_key.sign_logout_token(&claims)?,
            jti,
            now,
            now + 300,
        ))
    }
    fn claim(&self, client: &str, owner: &str, now: u64, candidate: Option<Candidate>) -> Request {
        self.request(
            client,
            Command::Claim {
                candidate,
                owner: owner.to_string(),
                timeout: 2,
            },
            now,
        )
    }
    fn apply(&self, request: &Request) -> TestResult<Outcome> {
        self.a
            .delivery_transition(request)
            .map_err(anyhow::Error::msg)
    }
}

fn permit(outcome: Outcome) -> TestResult<Permit> {
    if let Outcome::Granted(permit) = outcome {
        Ok(permit)
    } else {
        anyhow::bail!("expected claim")
    }
}

impl Drop for SessionFixture {
    fn drop(&mut self) {
        // Remove only this fixture's known keys. No FLUSH, shutdown, global scan or shared database mutation.
        if let Some((url, prefix)) = &self.redis {
            let cleanup = || -> ::redis::RedisResult<()> {
                let mut conn = ::redis::Client::open(url.as_str())?.get_connection()?;
                let key = format!("{prefix}:session:{}", self.event.sid);
                let aliases: Vec<Option<String>> = ::redis::cmd("HMGET")
                    .arg(&key)
                    .arg("auth_session_key")
                    .arg("user_sessions_key")
                    .query(&mut conn)?;
                let mut keys = vec![
                    key,
                    format!("{prefix}:clients:{}", self.event.sid),
                    format!("{prefix}:logged-out-expiries"),
                ];
                keys.extend(
                    aliases
                        .into_iter()
                        .flatten()
                        .filter(|key| key.starts_with(prefix)),
                );
                ::redis::cmd("DEL").arg(keys).query(&mut conn)
            };
            let _ = cleanup();
        }
    }
}
