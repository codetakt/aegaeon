use serde_json::json;
#[cfg(test)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::client_registry::ClientRegistry;
use crate::config::try_env_flag;
use crate::oidc::{OidcConfig, OidcLogoutEvent};

// Local issuance policy, independent of session-retention and ID Token TTLs.
const BACKCHANNEL_LOGOUT_TOKEN_LIFETIME_SECS: i64 = 300;

#[cfg(all(test, not(kani)))]
mod tests;

const BACKCHANNEL_LOGOUT_EVENT_URI: &str = "http://schemas.openid.net/event/backchannel-logout";
const BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV: &str =
    "AEGAEON_BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS";
#[cfg(test)]
#[allow(dead_code)]
const BACKCHANNEL_LOGOUT_HOST_LOCAL_BOOTSTRAP_ENV_KEYS: &[&str] =
    &[BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV];

#[cfg(test)]
fn build_backchannel_logout_claims(
    cfg: &OidcConfig,
    client_id: &str,
    session_id: &str,
    sub: Option<&str>,
    jti: &str,
) -> Result<serde_json::Value, String> {
    build_backchannel_logout_claims_at(cfg, client_id, session_id, sub, jti, SystemTime::now())
}

fn build_backchannel_logout_claims_at(
    cfg: &OidcConfig,
    client_id: &str,
    session_id: &str,
    sub: Option<&str>,
    jti: &str,
    issued_at: SystemTime,
) -> Result<serde_json::Value, String> {
    let now = issued_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock error".to_string())?
        .as_secs();
    let (now, exp) = logout_token_dates(now)?;

    if client_id.trim().is_empty() {
        return Err("client_id must not be blank".to_string());
    }
    if session_id.trim().is_empty() {
        return Err("sid must not be blank".to_string());
    }
    if jti.trim().is_empty() {
        return Err("jti must not be blank".to_string());
    }

    let mut claims = json!({
        "iss": cfg.issuer,
        "aud": client_id,
        "iat": now,
        "exp": exp,
        "jti": jti,
        "sid": session_id,
        "events": {
            BACKCHANNEL_LOGOUT_EVENT_URI: {},
        },
    });
    if let Some(sub) = sub {
        if sub.trim().is_empty() {
            return Err("sub must not be blank".to_string());
        }
        claims["sub"] = json!(sub);
    }

    Ok(claims)
}

fn logout_token_dates(seconds_since_epoch: u64) -> Result<(i64, i64), String> {
    let iat = i64::try_from(seconds_since_epoch)
        .map_err(|_| "system clock exceeds supported range".to_string())?;
    let exp = iat
        .checked_add(BACKCHANNEL_LOGOUT_TOKEN_LIFETIME_SECS)
        .ok_or_else(|| "logout token expiration exceeds supported range".to_string())?;
    Ok((iat, exp))
}

#[cfg(test)]
fn build_backchannel_logout_token(
    cfg: &OidcConfig,
    client_id: &str,
    session_id: &str,
    sub: Option<&str>,
    jti: &str,
) -> Result<String, String> {
    let claims = build_backchannel_logout_claims(cfg, client_id, session_id, sub, jti)?;
    cfg.signing_key
        .sign_logout_token(&claims)
        .map_err(|_| "failed to sign logout_token".to_string())
}

#[cfg(test)]
async fn build_backchannel_logout_token_async(
    cfg: &OidcConfig,
    client_id: &str,
    session_id: &str,
    sub: Option<&str>,
    jti: &str,
) -> Result<String, String> {
    let claims = build_backchannel_logout_claims(cfg, client_id, session_id, sub, jti)?;
    cfg.signing_key
        .sign_logout_token_async(&claims)
        .await
        .map_err(|_| "failed to sign logout_token".to_string())
}

pub(super) fn validate_backchannel_logout_dispatch_uri(uri: &str) -> Result<(), String> {
    let parsed = Url::parse(uri).map_err(|_| "invalid backchannel logout uri".to_string())?;
    if parsed.fragment().is_some() {
        return Err("backchannel logout uri must not include fragment".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("backchannel logout uri must not include userinfo".to_string());
    }
    if parsed.host_str().is_none() {
        return Err("backchannel logout uri must include host".to_string());
    }
    if parsed.scheme() != "https" {
        if allow_http_loopback_backchannel_logout_for_tests()
            && backchannel_logout_uri_targets_loopback_http(&parsed)
        {
            return Ok(());
        }
        return Err("backchannel logout uri must use https".to_string());
    }
    if crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err() {
        return Err("backchannel logout uri must not target non-routable hosts".to_string());
    }
    crate::ssrf::validate_url_not_private(uri).map_err(|err| err.to_string())
}

fn allow_http_loopback_backchannel_logout_for_tests() -> bool {
    if !crate::config::test_runtime_helpers_allowed_by_build() {
        return false;
    }
    match try_env_flag(BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV, false) {
        Ok(enabled) => enabled,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "invalid backchannel logout loopback test flag ignored"
            );
            false
        }
    }
}

fn backchannel_logout_uri_targets_loopback_http(uri: &Url) -> bool {
    uri.scheme() == "http" && uri.host_str().is_some_and(crate::util::is_loopback_host)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct BackchannelLogoutDispatchReport {
    pub(super) targeted_clients: usize,
    pub(super) delivered: usize,
    pub(super) sent: usize,
    pub(super) already_delivered: usize,
    pub(super) deferred: usize,
    pub(super) terminal_undelivered: usize,
    pub(super) legacy_unknown: usize,
    pub(super) storage_failures: usize,
    pub(super) unknown_outcomes: usize,
    pub(super) disabled_clients: usize,
    pub(super) skipped_unregistered_clients: usize,
    pub(super) skipped_without_logout_uri: usize,
    pub(super) rejected_logout_uri: usize,
    pub(super) token_build_failures: usize,
    pub(super) delivery_failures: usize,
    pub(super) http_client_init_failed: bool,
}

impl BackchannelLogoutDispatchReport {
    #[must_use]
    fn for_event(event: &OidcLogoutEvent) -> Self {
        Self {
            targeted_clients: event.client_ids.len(),
            ..Self::default()
        }
    }

    #[must_use]
    pub(super) const fn has_failures(&self) -> bool {
        self.terminal_undelivered > 0
            || self.legacy_unknown > 0
            || self.storage_failures > 0
            || self.unknown_outcomes > 0
            || self.deferred > 0
            || self.skipped_unregistered_clients > 0
            || self.skipped_without_logout_uri > 0
            || self.rejected_logout_uri > 0
            || self.token_build_failures > 0
            || self.delivery_failures > 0
            || self.http_client_init_failed
    }
}

#[cfg(not(kani))]
mod delivery;
#[cfg(all(test, not(kani)))]
pub(super) use delivery::dispatch_backchannel_logout;
#[cfg(not(kani))]
pub(super) use delivery::dispatch_backchannel_logout_async;

#[cfg(kani)]
pub(super) async fn dispatch_backchannel_logout_async(
    _cfg: &OidcConfig,
    _clients: &ClientRegistry,
    _sessions: Option<&crate::oidc::OidcSessionStore>,
    event: &OidcLogoutEvent,
) -> BackchannelLogoutDispatchReport {
    // The paused model has no delivery ownership semantics. Explicitly unavailable; never send.
    BackchannelLogoutDispatchReport {
        targeted_clients: event.client_ids.len(),
        storage_failures: event.client_ids.len(),
        ..BackchannelLogoutDispatchReport::default()
    }
}

#[cfg(all(test, kani))]
pub(super) fn dispatch_backchannel_logout(
    _cfg: &OidcConfig,
    _clients: &ClientRegistry,
    _sessions: Option<&crate::oidc::OidcSessionStore>,
    event: &OidcLogoutEvent,
) -> BackchannelLogoutDispatchReport {
    BackchannelLogoutDispatchReport {
        targeted_clients: event.client_ids.len(),
        storage_failures: event.client_ids.len(),
        ..BackchannelLogoutDispatchReport::default()
    }
}
