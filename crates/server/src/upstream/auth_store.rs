use super::store::upstream_auth_request_is_fresh_at;
use super::{
    UpstreamAttributeMapping, UpstreamAuthRequest, UpstreamClaimReleasePolicy,
    UpstreamConnectionContext, UpstreamJitProvisioningPolicy, UpstreamLogoutPolicy,
};
use crate::config::RuntimeStateNamespace;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub(super) const UPSTREAM_AUTH_REDIS_URL_ENV: &str = "AEGAEON_UPSTREAM_AUTH_REDIS_URL";
const CONSUME_STATE_SCRIPT: &str = r"
-- Seconds stay canonical decimal strings over the entire u64 domain.
local function canonical_decimal(value, maximum)
  return type(value) == 'string'
    and (value == '0' or string.match(value, '^[1-9][0-9]*$'))
    and (#value < #maximum or (#value == #maximum and value <= maximum))
end
local function expiry_is_live(seconds, nanos, now_seconds, now_micros)
  if not canonical_decimal(seconds, '18446744073709551615')
    or not canonical_decimal(now_seconds, '18446744073709551615')
    or not canonical_decimal(nanos, '999999999')
    or not canonical_decimal(now_micros, '999999') then
    return false
  end
  if #seconds ~= #now_seconds then return #seconds > #now_seconds end
  if seconds ~= now_seconds then return seconds > now_seconds end
  return tonumber(nanos) > tonumber(now_micros) * 1000
end
local payload = redis.call('GET', KEYS[1])
if not payload or payload ~= ARGV[1] then return nil end
local now = redis.call('TIME')
if not expiry_is_live(ARGV[2], ARGV[3], now[1], now[2]) then return nil end
redis.call('DEL', KEYS[1])
return payload
";
#[cfg(test)]
const CONSUME_STATE_SCRIPT_KEY_COUNT: usize = 1;
#[cfg(test)]
const CONSUME_STATE_SCRIPT_ARG_COUNT: usize = 3;

#[derive(Clone)]
pub(super) struct RedisUpstreamAuthStoreBackend {
    client: redis::Client,
    key: Arc<str>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct RedisUpstreamAuthRequest {
    #[serde(default)]
    pub(super) browser_binding_digest: Option<String>,
    pub(super) issuer_policy_version: u32,
    pub(super) state: String,
    pub(super) nonce: String,
    pub(super) code_verifier: Option<String>,
    pub(super) acr: Option<String>,
    pub(super) issuer: String,
    pub(super) client_id: String,
    pub(super) client_auth_method: String,
    pub(super) connection_id: String,
    pub(super) team_id: String,
    pub(super) tenant_id: String,
    pub(super) environment_id: String,
    pub(super) configuration_version_id: String,
    pub(super) token_endpoint: String,
    pub(super) jwks_uri: String,
    pub(super) redirect_uri: String,
    pub(super) return_to: Option<String>,
    pub(super) max_age: Option<i64>,
    pub(super) require_iss_parameter: bool,
    pub(super) jit_provisioning_policy: Option<UpstreamJitProvisioningPolicy>,
    pub(super) attribute_mappings: Vec<UpstreamAttributeMapping>,
    pub(super) claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub(super) logout_policy: Option<UpstreamLogoutPolicy>,
    pub(super) issued_at_epoch_secs: u64,
    pub(super) expires_at_epoch_secs: u64,
    #[serde(default)]
    pub(super) expires_at_subsec_nanos: u32,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum UpstreamAuthStorageError {
    #[error("upstream auth store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("upstream auth state already exists")]
    Collision,
    #[error("upstream auth store payload cannot be encoded: {0}")]
    Codec(String),
}

fn parse_required_uuid(value: &str) -> Result<uuid::Uuid, UpstreamAuthStorageError> {
    uuid::Uuid::parse_str(value).map_err(|err| UpstreamAuthStorageError::Codec(err.to_string()))
}

fn context_uuid_strings(
    context: UpstreamConnectionContext,
) -> (String, String, String, String, String) {
    (
        context.connection_id.to_string(),
        context.team_id.to_string(),
        context.tenant_id.to_string(),
        context.environment_id.to_string(),
        context.configuration_version_id.to_string(),
    )
}

fn parse_upstream_auth_request_context(
    connection_id: &str,
    team_id: &str,
    tenant_id: &str,
    environment_id: &str,
    configuration_version_id: &str,
) -> Result<UpstreamConnectionContext, UpstreamAuthStorageError> {
    Ok(UpstreamConnectionContext::new(
        parse_required_uuid(connection_id)?,
        parse_required_uuid(team_id)?,
        parse_required_uuid(tenant_id)?,
        parse_required_uuid(environment_id)?,
        parse_required_uuid(configuration_version_id)?,
    ))
}

fn system_time_epoch_secs(time: SystemTime) -> Option<u64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn system_time_from_epoch_secs(secs: u64) -> Result<SystemTime, UpstreamAuthStorageError> {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or_else(|| UpstreamAuthStorageError::Codec("epoch seconds overflow".into()))
}

fn system_time_from_epoch_parts(
    secs: u64,
    nanos: u32,
) -> Result<SystemTime, UpstreamAuthStorageError> {
    aegaeon_pure::upstream_deadline::system_time_from_epoch_parts(secs, nanos)
        .map_err(|err| UpstreamAuthStorageError::Codec(err.message().into()))
}

fn redis_ttl_millis_at(
    expires_at: SystemTime,
    now: SystemTime,
) -> Result<u64, UpstreamAuthStorageError> {
    aegaeon_pure::upstream_deadline::redis_ttl_millis_at(expires_at, now)
        .map_err(|err| UpstreamAuthStorageError::Codec(err.message().into()))
}

fn redis_ttl_millis_until(expires_at: SystemTime) -> Result<u64, UpstreamAuthStorageError> {
    redis_ttl_millis_at(expires_at, SystemTime::now())
}

impl RedisUpstreamAuthStoreBackend {
    pub(super) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, UpstreamAuthStorageError> {
        Self::new_with_key(url, namespace.redis_prefix("upstream-auth", "v2"))
    }

    pub(super) fn new_with_key(
        url: &str,
        key: impl Into<Arc<str>>,
    ) -> Result<Self, UpstreamAuthStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                key: key.into(),
            })
            .map_err(|err| UpstreamAuthStorageError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, UpstreamAuthStorageError> {
        self.client
            .get_connection()
            .map_err(|err| UpstreamAuthStorageError::BackendUnavailable(err.to_string()))
    }

    fn state_key(&self, state: &str) -> String {
        format!(
            "{}:{}",
            self.key,
            aegaeon_crypto::hash::sha256_hex(state.as_bytes())
        )
    }

    pub(super) fn insert(
        &self,
        request: &UpstreamAuthRequest,
    ) -> Result<(), UpstreamAuthStorageError> {
        let dto = RedisUpstreamAuthRequest::from_request(request)?;
        let payload = serde_json::to_string(&dto)
            .map_err(|err| UpstreamAuthStorageError::Codec(err.to_string()))?;
        let ttl_millis = redis_ttl_millis_until(request.expires_at)?;
        let key = self.state_key(&request.state);
        let mut conn = self.connection()?;
        match redis::cmd("SET")
            .arg(key)
            .arg(payload)
            .arg("NX")
            .arg("PX")
            .arg(ttl_millis)
            .query::<redis::Value>(&mut conn)
            .map_err(|err| UpstreamAuthStorageError::BackendUnavailable(err.to_string()))?
        {
            redis::Value::Okay => Ok(()),
            redis::Value::Nil => Err(UpstreamAuthStorageError::Collision),
            other => Err(UpstreamAuthStorageError::BackendUnavailable(format!(
                "unexpected Redis SET response: {other:?}"
            ))),
        }
    }

    pub(super) fn consume_bound(
        &self,
        state: &str,
        browser_digest: &str,
        redirect_uri: &str,
    ) -> Result<Option<UpstreamAuthRequest>, UpstreamAuthStorageError> {
        let key = self.state_key(state);
        let mut conn = self.connection()?;
        // Decode exactly before consuming. The following atomic byte comparison binds
        // admission to this validated snapshot despite the additional Redis read.
        let Some(payload) = redis::cmd("GET")
            .arg(&key)
            .query::<Option<String>>(&mut conn)
            .map_err(|err| UpstreamAuthStorageError::BackendUnavailable(err.to_string()))?
        else {
            return Ok(None);
        };
        let dto = serde_json::from_str::<RedisUpstreamAuthRequest>(&payload).map_err(|_| {
            UpstreamAuthStorageError::Codec("invalid upstream auth state payload".into())
        })?;
        let seconds = dto.expires_at_epoch_secs.to_string();
        let nanos = dto.expires_at_subsec_nanos.to_string();
        let request = dto.into_request()?;
        if !super::store::valid_browser_binding_digest(browser_digest)
            || request.state != state
            || !request
                .browser_binding_digest
                .as_deref()
                .is_some_and(|stored| {
                    crate::util::constant_time_eq(stored.as_bytes(), browser_digest.as_bytes())
                })
            || request.redirect_uri != redirect_uri
            || !upstream_auth_request_is_fresh_at(&request, SystemTime::now())
        {
            return Ok(None);
        }
        let consumed = redis::Script::new(CONSUME_STATE_SCRIPT)
            .key(key)
            .arg(&payload)
            .arg(seconds)
            .arg(nanos)
            .invoke::<Option<String>>(&mut conn)
            .map_err(|err| UpstreamAuthStorageError::BackendUnavailable(err.to_string()))?;
        // A consumed snapshot must also still be fresh when returned to the caller.
        // If transport delay or clock differences cross the deadline, fail closed;
        // the authorization must restart rather than reuse the consumed state.
        Ok(consumed
            .filter(|_| upstream_auth_request_is_fresh_at(&request, SystemTime::now()))
            .map(|_| request))
    }
}

impl RedisUpstreamAuthRequest {
    pub(super) fn from_request(
        request: &UpstreamAuthRequest,
    ) -> Result<Self, UpstreamAuthStorageError> {
        let issued_at_epoch_secs = system_time_epoch_secs(request.issued_at)
            .ok_or_else(|| UpstreamAuthStorageError::Codec("issued_at before Unix epoch".into()))?;
        let expiry = request
            .expires_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| UpstreamAuthStorageError::Codec("expires_at before Unix epoch".into()))?;
        let (connection_id, team_id, tenant_id, environment_id, configuration_version_id) =
            context_uuid_strings(request.context);
        Ok(Self {
            issuer_policy_version: aegaeon_pure::upstream_issuer::POLICY_VERSION,
            browser_binding_digest: request.browser_binding_digest.clone(),
            state: request.state.clone(),
            nonce: request.nonce.clone(),
            code_verifier: request.code_verifier.clone(),
            acr: request.acr.clone(),
            issuer: request.issuer.clone(),
            client_id: request.client_id.clone(),
            client_auth_method: request.client_auth_method.clone(),
            connection_id,
            team_id,
            tenant_id,
            environment_id,
            configuration_version_id,
            token_endpoint: request.token_endpoint.clone(),
            jwks_uri: request.jwks_uri.clone(),
            redirect_uri: request.redirect_uri.clone(),
            return_to: request.return_to.clone(),
            max_age: request.max_age,
            require_iss_parameter: request.require_iss_parameter,
            jit_provisioning_policy: request.jit_provisioning_policy.clone(),
            attribute_mappings: request.attribute_mappings.clone(),
            claim_release_policy: request.claim_release_policy.clone(),
            logout_policy: request.logout_policy.clone(),
            issued_at_epoch_secs,
            expires_at_epoch_secs: expiry.as_secs(),
            expires_at_subsec_nanos: expiry.subsec_nanos(),
        })
    }

    pub(super) fn into_request(self) -> Result<UpstreamAuthRequest, UpstreamAuthStorageError> {
        if !aegaeon_pure::upstream_issuer::supported_policy_version(self.issuer_policy_version) {
            return Err(UpstreamAuthStorageError::Codec(
                "unsupported upstream issuer policy".into(),
            ));
        }
        Ok(UpstreamAuthRequest {
            browser_binding_digest: self.browser_binding_digest,
            state: self.state,
            nonce: self.nonce,
            code_verifier: self.code_verifier,
            acr: self.acr,
            issuer: self.issuer,
            client_id: self.client_id,
            client_secret: None,
            client_auth_method: self.client_auth_method,
            context: parse_upstream_auth_request_context(
                &self.connection_id,
                &self.team_id,
                &self.tenant_id,
                &self.environment_id,
                &self.configuration_version_id,
            )?,
            token_endpoint: self.token_endpoint,
            jwks_uri: self.jwks_uri,
            redirect_uri: self.redirect_uri,
            return_to: self.return_to,
            max_age: self.max_age,
            require_iss_parameter: self.require_iss_parameter,
            jit_provisioning_policy: self.jit_provisioning_policy,
            attribute_mappings: self.attribute_mappings,
            claim_release_policy: self.claim_release_policy,
            logout_policy: self.logout_policy,
            issued_at: system_time_from_epoch_secs(self.issued_at_epoch_secs)?,
            expires_at: system_time_from_epoch_parts(
                self.expires_at_epoch_secs,
                self.expires_at_subsec_nanos,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    fn referenced_indexes(script: &str, prefix: &str) -> Vec<usize> {
        let marker = format!("{prefix}[");
        script
            .match_indices(&marker)
            .filter_map(|(offset, _)| {
                let start = offset + marker.len();
                let digits: String = script[start..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect();
                digits.parse::<usize>().ok()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn expected_indexes(len: usize) -> Vec<usize> {
        (1..=len).collect()
    }

    fn invocation_body<'a>(source: &'a str, name: &str, invoke_marker: &str) -> &'a str {
        let start = source
            .find(name)
            .expect("script invocation function should exist");
        let rest = &source[start..];
        let end = rest
            .find(invoke_marker)
            .expect("script invocation should end with Redis invoke");
        &rest[..end]
    }

    fn assert_script_contract(script: &str, key_count: usize, arg_count: usize, body: &str) {
        assert_eq!(
            referenced_indexes(script, "KEYS"),
            expected_indexes(key_count)
        );
        assert_eq!(
            referenced_indexes(script, "ARGV"),
            expected_indexes(arg_count)
        );
        assert_eq!(body.matches(".key(").count(), key_count);
        assert_eq!(body.matches(".arg(").count(), arg_count);
    }

    #[test]
    fn expiry_parts_and_ceiling_ttl_preserve_boundaries() {
        use super::*;
        let epoch = SystemTime::UNIX_EPOCH;
        for nanos in [0, 1, 999_999_999] {
            assert_eq!(
                system_time_from_epoch_parts(42, nanos).unwrap(),
                epoch + Duration::new(42, nanos)
            );
        }
        assert!(system_time_from_epoch_parts(42, 1_000_000_000).is_err());
        for seconds in [
            9_007_199_254_740_991,
            9_007_199_254_740_992,
            9_007_199_254_740_993,
            u64::MAX,
        ] {
            let expected = epoch.checked_add(Duration::new(seconds, 999_999_999));
            assert_eq!(
                system_time_from_epoch_parts(seconds, 999_999_999).ok(),
                expected
            );
        }
        for (nanos, millis) in [
            (1, 1),
            (999_999, 1),
            (1_000_000, 1),
            (1_000_001, 2),
            (999_999_999, 1000),
        ] {
            assert_eq!(
                redis_ttl_millis_at(epoch + Duration::from_nanos(nanos), epoch).unwrap(),
                millis
            );
        }
        assert!(redis_ttl_millis_at(epoch, epoch).is_err());
        assert!(redis_ttl_millis_at(epoch, epoch + Duration::from_nanos(1)).is_err());
        if let Some(far_future) = epoch.checked_add(Duration::from_secs(u64::MAX / 1000 + 1)) {
            assert!(redis_ttl_millis_at(far_future, epoch).is_err());
        }
    }

    #[test]
    #[ignore = "requires AEGAEON_TEST_REDIS_URL"]
    fn redis_expiry_decimal_comparator_and_snapshot_cas() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::*;
        let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
        let mut conn = redis::Client::open(url)?.get_connection()?;
        // Execute the production helper with supplied clocks. This is domain coverage,
        // not evidence that a real Redis clock reached these future timestamps.
        let helper = CONSUME_STATE_SCRIPT
            .split("local payload =")
            .next()
            .unwrap();
        let script = redis::Script::new(&format!(
            "{helper}\nreturn expiry_is_live(ARGV[1], ARGV[2], ARGV[3], ARGV[4])"
        ));
        for (expiry, nanos, now, micros, live) in [
            ("0", "1", "0", "0", true),
            ("9", "999999999", "10", "0", false),
            ("10", "0", "9", "999999", true),
            ("9007199254740993", "0", "9007199254740992", "0", true),
            (
                "9007199254740992",
                "999999999",
                "9007199254740993",
                "0",
                false,
            ),
            (
                "18446744073709551615",
                "1",
                "18446744073709551615",
                "0",
                true,
            ),
            (
                "18446744073709551615",
                "1000",
                "18446744073709551615",
                "1",
                false,
            ),
            ("42", "999999999", "42", "999999", true),
            ("18446744073709551616", "0", "0", "0", false),
            ("01", "1", "0", "0", false),
            ("-1", "1", "0", "0", false),
            ("1e3", "1", "0", "0", false),
            ("1", "1000000000", "0", "0", false),
            ("1", "NaN", "0", "0", false),
            ("1", "-1", "0", "0", false),
            ("1", "1.5", "0", "0", false),
        ] {
            let actual: bool = script
                .arg(expiry)
                .arg(nanos)
                .arg(now)
                .arg(micros)
                .invoke(&mut conn)?;
            assert_eq!(actual, live, "expiry={expiry}.{nanos}, now={now}/{micros}");
        }
        let key = format!("upstream-cas-test:{}", uuid::Uuid::new_v4());
        redis::cmd("SET")
            .arg(&key)
            .arg("original")
            .query::<()>(&mut conn)?;
        let snapshot: String = redis::cmd("GET").arg(&key).query(&mut conn)?;
        redis::cmd("SET")
            .arg(&key)
            .arg("replacement")
            .query::<()>(&mut conn)?;
        let script = redis::Script::new(CONSUME_STATE_SCRIPT);
        let stale: Option<String> = script
            .key(&key)
            .arg(&snapshot)
            .arg(u64::MAX.to_string())
            .arg("0")
            .invoke(&mut conn)?;
        assert!(stale.is_none());
        let current: String = redis::cmd("GET").arg(&key).query(&mut conn)?;
        assert_eq!(current, "replacement");
        let consumed: Option<String> = script
            .key(&key)
            .arg(&current)
            .arg(u64::MAX.to_string())
            .arg("0")
            .invoke(&mut conn)?;
        assert_eq!(consumed.as_deref(), Some("replacement"));
        let replay: Option<String> = script
            .key(&key)
            .arg(&current)
            .arg(u64::MAX.to_string())
            .arg("0")
            .invoke(&mut conn)?;
        assert!(replay.is_none());
        Ok(())
    }

    #[test]
    fn consume_state_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("auth_store.rs");
        let body = invocation_body(
            source,
            "let consumed = redis::Script::new(CONSUME_STATE_SCRIPT)",
            ".invoke::<Option<String>>(",
        );
        assert_script_contract(
            super::CONSUME_STATE_SCRIPT,
            super::CONSUME_STATE_SCRIPT_KEY_COUNT,
            super::CONSUME_STATE_SCRIPT_ARG_COUNT,
            body,
        );
    }
}
