use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

use crate::client_registry::ClientRegistry;
use crate::config::try_env_flag;
use crate::oidc::{OidcConfig, OidcLogoutEvent};

const BACKCHANNEL_LOGOUT_EVENT_URI: &str = "http://schemas.openid.net/event/backchannel-logout";
const BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV: &str =
    "AEGAEON_BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS";
#[cfg(test)]
#[allow(dead_code)]
const BACKCHANNEL_LOGOUT_HOST_LOCAL_BOOTSTRAP_ENV_KEYS: &[&str] =
    &[BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV];

fn build_backchannel_logout_claims(
    cfg: &OidcConfig,
    client_id: &str,
    session_id: &str,
    sub: Option<&str>,
    jti: &str,
) -> Result<serde_json::Value, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock error".to_string())?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| "system clock exceeds supported range".to_string())?;

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
        .sign_rs256_jwt(&claims)
        .map_err(|_| "failed to sign logout_token".to_string())
}

async fn build_backchannel_logout_token_async(
    cfg: &OidcConfig,
    client_id: &str,
    session_id: &str,
    sub: Option<&str>,
    jti: &str,
) -> Result<String, String> {
    let claims = build_backchannel_logout_claims(cfg, client_id, session_id, sub, jti)?;
    cfg.signing_key
        .sign_rs256_jwt_async(&claims)
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
        self.skipped_unregistered_clients > 0
            || self.skipped_without_logout_uri > 0
            || self.rejected_logout_uri > 0
            || self.token_build_failures > 0
            || self.delivery_failures > 0
            || self.http_client_init_failed
    }
}

struct BackchannelLogoutTarget {
    client_id: String,
    uri: String,
    sub: Option<String>,
}

fn resolve_backchannel_logout_target(
    clients: &ClientRegistry,
    event: &OidcLogoutEvent,
    client_id: &str,
    report: &mut BackchannelLogoutDispatchReport,
) -> Option<BackchannelLogoutTarget> {
    let registered = match clients.try_get(client_id) {
        Ok(Some(registered)) => registered,
        Ok(None) => {
            report.skipped_unregistered_clients += 1;
            tracing::debug!(
                client_id = %client_id,
                "backchannel logout skipped unregistered client"
            );
            return None;
        }
        Err(error) => {
            report.delivery_failures += 1;
            tracing::error!(
                client_id = %client_id,
                error = %error,
                "backchannel logout client registry lookup failed"
            );
            return None;
        }
    };
    let Some(uri) = registered.backchannel_logout_uri.clone() else {
        report.skipped_without_logout_uri += 1;
        tracing::debug!(
            client_id = %client_id,
            "backchannel logout skipped client without backchannel_logout_uri"
        );
        return None;
    };
    if let Err(err) = validate_backchannel_logout_dispatch_uri(&uri) {
        report.rejected_logout_uri += 1;
        tracing::warn!(client_id = %client_id, error = %err, "backchannel logout uri rejected");
        return None;
    }

    let sub = (!registered.backchannel_logout_session_required).then(|| event.user_id.clone());
    Some(BackchannelLogoutTarget {
        client_id: client_id.to_string(),
        uri,
        sub,
    })
}

#[cfg(test)]
pub(super) fn dispatch_backchannel_logout(
    cfg: &OidcConfig,
    clients: &ClientRegistry,
    event: &OidcLogoutEvent,
) -> BackchannelLogoutDispatchReport {
    let mut report = BackchannelLogoutDispatchReport::for_event(event);
    let timeout = Duration::from_secs(cfg.backchannel_logout_timeout_secs.max(1));
    let mut http = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(crate::ssrf::build_redirect_policy(None));
    if !allow_http_loopback_backchannel_logout_for_tests() {
        http = http
            .dns_resolver(Arc::new(crate::ssrf::NonRoutableDnsResolver))
            .https_only(true);
    }
    let http = match http.build() {
        Ok(http) => http,
        Err(err) => {
            report.http_client_init_failed = true;
            tracing::error!(
                error = %err,
                "backchannel logout HTTP client initialization failed"
            );
            return report;
        }
    };

    for client_id in &event.client_ids {
        let Some(target) =
            resolve_backchannel_logout_target(clients, event, client_id, &mut report)
        else {
            continue;
        };
        let token = match build_backchannel_logout_token(
            cfg,
            &target.client_id,
            &event.sid,
            target.sub.as_deref(),
            &event.jti,
        ) {
            Ok(token) => token,
            Err(err) => {
                report.token_build_failures += 1;
                tracing::warn!(
                    client_id = %client_id,
                    error = %err,
                    "backchannel logout token build failed"
                );
                continue;
            }
        };

        match http
            .post(&target.uri)
            .form(&[("logout_token", token)])
            .send()
        {
            Ok(resp) if resp.status().is_success() => {
                report.delivered += 1;
            }
            Ok(resp) => {
                report.delivery_failures += 1;
                tracing::warn!(
                    client_id = %client_id,
                    status = %resp.status(),
                    "backchannel logout delivery failed"
                );
            }
            Err(err) => {
                report.delivery_failures += 1;
                tracing::warn!(
                    client_id = %client_id,
                    error = %err,
                    "backchannel logout delivery error"
                );
            }
        }
    }

    report
}

pub(super) async fn dispatch_backchannel_logout_async(
    cfg: &OidcConfig,
    clients: &ClientRegistry,
    event: &OidcLogoutEvent,
) -> BackchannelLogoutDispatchReport {
    let mut report = BackchannelLogoutDispatchReport::for_event(event);
    let timeout = Duration::from_secs(cfg.backchannel_logout_timeout_secs.max(1));
    let mut http = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(crate::ssrf::build_redirect_policy(None));
    if !allow_http_loopback_backchannel_logout_for_tests() {
        http = http
            .dns_resolver(Arc::new(crate::ssrf::NonRoutableDnsResolver))
            .https_only(true);
    }
    let http = match http.build() {
        Ok(http) => http,
        Err(err) => {
            report.http_client_init_failed = true;
            tracing::error!(
                error = %err,
                "backchannel logout HTTP client initialization failed"
            );
            return report;
        }
    };

    for client_id in &event.client_ids {
        let Some(target) =
            resolve_backchannel_logout_target(clients, event, client_id, &mut report)
        else {
            continue;
        };
        let token = match build_backchannel_logout_token_async(
            cfg,
            &target.client_id,
            &event.sid,
            target.sub.as_deref(),
            &event.jti,
        )
        .await
        {
            Ok(token) => token,
            Err(err) => {
                report.token_build_failures += 1;
                tracing::warn!(
                    client_id = %target.client_id,
                    error = %err,
                    "backchannel logout token build failed"
                );
                continue;
            }
        };

        match http
            .post(&target.uri)
            .form(&[("logout_token", token)])
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                report.delivered += 1;
            }
            Ok(resp) => {
                report.delivery_failures += 1;
                tracing::warn!(
                    client_id = %target.client_id,
                    status = %resp.status(),
                    "backchannel logout delivery failed"
                );
            }
            Err(err) => {
                report.delivery_failures += 1;
                tracing::warn!(
                    client_id = %target.client_id,
                    error = %err,
                    "backchannel logout delivery error"
                );
            }
        }
    }

    report
}
