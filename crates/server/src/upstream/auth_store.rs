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
local payload = redis.call('GET', KEYS[1])
if payload then
  redis.call('DEL', KEYS[1])
end
return payload
";
#[cfg(test)]
const CONSUME_STATE_SCRIPT_KEY_COUNT: usize = 1;
#[cfg(test)]
const CONSUME_STATE_SCRIPT_ARG_COUNT: usize = 0;

#[derive(Clone)]
pub(super) struct RedisUpstreamAuthStoreBackend {
    client: redis::Client,
    key: Arc<str>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct RedisUpstreamAuthRequest {
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

fn redis_ttl_millis_until(expires_at: SystemTime) -> Result<u64, UpstreamAuthStorageError> {
    expires_at
        .duration_since(SystemTime::now())
        .map_err(|_| {
            UpstreamAuthStorageError::Codec("upstream auth state is already expired".into())
        })
        .and_then(|ttl| {
            u64::try_from(ttl.as_millis().max(1))
                .map_err(|_| UpstreamAuthStorageError::Codec("upstream auth ttl overflow".into()))
        })
}

impl RedisUpstreamAuthStoreBackend {
    pub(super) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, UpstreamAuthStorageError> {
        Self::new_with_key(url, namespace.redis_prefix("upstream-auth", "v1"))
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

    pub(super) fn consume(
        &self,
        state: &str,
    ) -> Result<Option<UpstreamAuthRequest>, UpstreamAuthStorageError> {
        let key = self.state_key(state);
        let mut conn = self.connection()?;
        let payload = redis::Script::new(CONSUME_STATE_SCRIPT)
            .key(key)
            .invoke::<Option<String>>(&mut conn)
            .map_err(|err| UpstreamAuthStorageError::BackendUnavailable(err.to_string()))?;
        payload
            .map(|payload| {
                serde_json::from_str::<RedisUpstreamAuthRequest>(&payload)
                    .map_err(|err| UpstreamAuthStorageError::Codec(err.to_string()))
                    .and_then(|dto| dto.into_request())
                    .map(|request| {
                        upstream_auth_request_is_fresh_at(&request, SystemTime::now())
                            .then_some(request)
                    })
            })
            .transpose()
            .map(Option::flatten)
    }
}

impl RedisUpstreamAuthRequest {
    fn from_request(request: &UpstreamAuthRequest) -> Result<Self, UpstreamAuthStorageError> {
        let issued_at_epoch_secs = system_time_epoch_secs(request.issued_at)
            .ok_or_else(|| UpstreamAuthStorageError::Codec("issued_at before Unix epoch".into()))?;
        let expires_at_epoch_secs =
            system_time_epoch_secs(request.expires_at).ok_or_else(|| {
                UpstreamAuthStorageError::Codec("expires_at before Unix epoch".into())
            })?;
        let (connection_id, team_id, tenant_id, environment_id, configuration_version_id) =
            context_uuid_strings(request.context);
        Ok(Self {
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
            expires_at_epoch_secs,
        })
    }

    pub(super) fn into_request(self) -> Result<UpstreamAuthRequest, UpstreamAuthStorageError> {
        Ok(UpstreamAuthRequest {
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
            expires_at: system_time_from_epoch_secs(self.expires_at_epoch_secs)?,
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
    fn consume_state_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("auth_store.rs");
        let body = invocation_body(
            source,
            "pub(super) fn consume(",
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
