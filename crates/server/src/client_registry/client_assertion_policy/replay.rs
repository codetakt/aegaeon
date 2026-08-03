use aegaeon_jose::jwt::JwtClaims;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

use crate::config::{
    require_shared_runtime_store_url, valid_client_assertion_replay_window_secs, ConfigError,
    RuntimeStateNamespace, MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS,
};
use crate::middleware::{
    replay_key_material, RedisReplayStore, ReplayEntry, ReplayStore, ReplayStoreError,
};

use super::super::{metrics, ClientRegistryInitError};

pub(super) fn validate_client_assertion_replay_window(
    key: &str,
    value: i64,
) -> Result<i64, ConfigError> {
    if valid_client_assertion_replay_window_secs(value) {
        return Ok(value);
    }
    Err(ConfigError::InvalidNumberRange {
        key: key.to_string(),
        value: value.to_string(),
        expectation: format!("a value in 1..={MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS} seconds"),
    })
}

pub(in crate::client_registry) fn jwt_replay_store_from_env(
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<Arc<dyn ReplayStore>, ClientRegistryInitError> {
    let url = require_shared_runtime_store_url(
        "client assertion replay store",
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
    )?;
    RedisReplayStore::new(
        url.as_str(),
        runtime_state_namespace,
        "client-assertion-replay",
    )
    .map(|store| Arc::new(store) as Arc<dyn ReplayStore>)
    .map_err(|err| ClientRegistryInitError::ReplayStore(err.to_string()))
}

#[cfg(test)]
pub(in crate::client_registry) fn jwt_replay_material(client_id: &str, jti: &str) -> Vec<u8> {
    replay_key_material(&[client_id.as_bytes(), jti.as_bytes()])
}

pub(in crate::client_registry) fn record_jwt_replay(
    replay_store: &Arc<dyn ReplayStore>,
    namespace: &'static str,
    client_id: &str,
    jti: &str,
    window_secs: i64,
) -> Result<(), ReplayStoreError> {
    let ttl_secs = u64::try_from(window_secs).unwrap_or(1).max(1);
    let material = replay_key_material(&[client_id.as_bytes(), jti.as_bytes()]);
    let entry = ReplayEntry::new(namespace, &material, Duration::from_secs(ttl_secs));
    match replay_store.check_and_store(entry) {
        Ok(()) => Ok(()),
        Err(error) => {
            warn!(
                target: "jwks",
                client_id = %client_id,
                namespace,
                error = %error,
                "jwt assertion replay check failed"
            );
            Err(error)
        }
    }
}

pub(in crate::client_registry) fn assertion_replay_ttl_secs(
    claims: &JwtClaims,
    now: i64,
    leeway_secs: u64,
    replay_window_secs: i64,
    metric_label: &'static str,
    temporal_metric_label: &'static str,
    client_id: &str,
) -> Option<i64> {
    let exp = claims.exp?;
    let Some(remaining_validity) = exp.checked_sub(now) else {
        record_assertion_replay_temporal_failure(temporal_metric_label, client_id, exp, now);
        return None;
    };
    if remaining_validity > replay_window_secs {
        metrics::record_runtime_bcp_noncompliant(metric_label);
        warn!(
            target: "jwks",
            client_id = %client_id,
            exp,
            now,
            replay_window_secs,
            "jwt assertion exp exceeds replay protection window"
        );
        return None;
    }

    let Some(leeway) = i64::try_from(leeway_secs).ok() else {
        record_assertion_replay_temporal_failure(temporal_metric_label, client_id, exp, now);
        return None;
    };
    let Some(expires_with_leeway) = exp.checked_add(leeway) else {
        record_assertion_replay_temporal_failure(temporal_metric_label, client_id, exp, now);
        return None;
    };
    let Some(ttl) = expires_with_leeway.checked_sub(now) else {
        record_assertion_replay_temporal_failure(temporal_metric_label, client_id, exp, now);
        return None;
    };
    Some(ttl.max(1))
}

fn record_assertion_replay_temporal_failure(
    metric_label: &'static str,
    client_id: &str,
    exp: i64,
    now: i64,
) {
    metrics::record_runtime_bcp_noncompliant(metric_label);
    warn!(
        target: "jwks",
        client_id = %client_id,
        exp,
        now,
        "jwt assertion replay ttl temporal arithmetic failed"
    );
}
