use aegaeon_jose::RequestObjectError;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockWriteGuard};
use thiserror::Error;
use tracing::{debug, warn};

mod assertions;
mod client_assertion_policy;
mod client_queries;
mod client_types;
mod construction;
mod jwks_cache_control;
mod jwks_circuit;
mod jwks_fetch;
mod jwks_fetch_context;
mod jwks_fetch_memory;
mod jwks_gc;
mod jwks_policy;
mod jwks_refresh;
mod jwks_runtime_state;
mod jwks_types;
mod jwks_url;
mod jwks_validation;
#[cfg(kani)]
mod kani_helpers;
mod metrics;
mod registry_store;
mod request_object_keys;

#[cfg(test)]
use crate::config::try_env_flag;
use crate::config::ConfigError;
#[cfg(test)]
use crate::config::MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS;
use crate::middleware::ReplayStore;

#[cfg(test)]
use client_assertion_policy::jwt_replay_material;
use client_assertion_policy::{
    assertion_replay_ttl_secs, client_assertion_clock_error,
    client_assertion_error_from_jose_header, client_jwt_algorithm_name,
    jwt_algorithm_allowed_by_profile, jwt_algorithm_name, jwt_replay_store_from_env,
    record_jwt_replay, request_object_error_from_jose_header, require_non_empty_jti,
    signed_assertion_error_result,
};
pub use client_assertion_policy::{
    ClientAssertionRuntimePolicy, ClientAssertionValidationError, ClientAssertionValidationResult,
};
use client_assertion_policy::{JWT_BEARER_REPLAY_NAMESPACE, PRIVATE_KEY_JWT_REPLAY_NAMESPACE};
pub(crate) use client_types::verify_client_secret_material;
use client_types::{select_registration_token_match, verify_dummy_client_secret};
pub use client_types::{
    verify_client_secret_credentials, ClientSecretCredential, RegisteredClient,
    RegisteredClientJwks,
};

#[cfg(test)]
use jwks_cache_control::parse_cache_control;
use jwks_circuit::record_jwks_shared_runtime_state_failure;
#[cfg(test)]
use jwks_circuit::{circuit_allow_fetch, circuit_on_failure, circuit_on_success, circuit_phase};
#[cfg(test)]
use jwks_circuit::{
    circuit_allow_fetch_with_state, circuit_on_failure_with_state, circuit_phase_with_state,
};
pub use jwks_policy::JwksRuntimePolicy;
pub(crate) use jwks_policy::DEFAULT_JWKS_LOCAL_CACHE_MAX_ENTRIES;
use jwks_policy::MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS;
#[cfg(test)]
use jwks_policy::{
    valid_jwks_cache_gc_interval_secs, valid_jwks_cache_ttl_secs, valid_jwks_circuit_reset_secs,
    valid_jwks_http_retries, valid_jwks_http_timeout_secs, valid_jwks_local_cache_max_entries,
    valid_jwks_refresh_skew_secs, MAX_JWKS_CACHE_GC_INTERVAL_SECS, MAX_JWKS_CACHE_TTL_SECS,
    MAX_JWKS_CIRCUIT_RESET_SECS, MAX_JWKS_HTTP_RETRIES, MAX_JWKS_HTTP_TIMEOUT_SECS,
    MAX_JWKS_LOCAL_CACHE_MAX_ENTRIES, MAX_JWKS_REFRESH_SKEW_SECS,
};
#[cfg(test)]
use jwks_refresh::{decode_fetched_jwks_body, spawn_jwks_refresh_once};
#[cfg(test)]
use jwks_runtime_state::CircuitPhase;
#[cfg(test)]
use jwks_runtime_state::CircuitState;
#[cfg(test)]
use jwks_runtime_state::RedisJwksRuntimeState;
use jwks_runtime_state::{JwksRuntimeState, JwksSharedRuntimeState, JwksSharedStateError};
#[cfg(test)]
use jwks_types::{CacheEntry, FetchedJwk, FetchedJwks};
#[cfg(test)]
use jwks_url::{
    jwks_http_loopback_allowed_for_tests, jwks_insecure_skip_verify_allowed,
    validate_jwks_fetch_url,
};
#[cfg(test)]
use jwks_validation::has_duplicate_kid;
#[cfg(test)]
use jwks_validation::kid_reuse_changed;
#[cfg(kani)]
pub use kani_helpers::{
    KaniFetchedJwk, __circuit_allow_fetch, __circuit_force_half_open, __circuit_on_failure,
    __circuit_on_success, __circuit_phase, __circuit_reset, __has_duplicate_kid,
    __kid_reuse_changed, __parse_cache_control_val, __select_jwk_tuple, __sha256_hex,
};
#[cfg(test)]
use request_object_keys::rsa_public_components_from_public_pem;

type ResolvedJwkParts = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[cfg(test)]
const SEEDED_TEST_CLIENTS_BUILD_GUARD: &str = "seeded_test_clients";
const JWKS_REDIS_URL_ENV: &str = "AEGAEON_JWKS_REDIS_URL";
#[derive(Debug, Error)]
pub enum ClientRegistryInitError {
    #[error("failed to initialize client assertion replay Redis store: {0}")]
    ReplayStore(String),

    #[error("failed to initialize JWKS Redis runtime state: {0}")]
    JwksSharedState(String),

    #[error(transparent)]
    Config(#[from] ConfigError),
}

fn unix_epoch_now_i64(context: &'static str) -> Option<i64> {
    crate::util::now_unix_epoch_secs_i64()
        .inspect_err(|err| {
            crate::util::log_clock_error(context, err);
        })
        .ok()
}

#[derive(Debug, Error)]
pub enum RequestObjectValidationError {
    #[error("client `{0}` is not registered")]
    ClientNotRegistered(String),

    #[error("client `{0}` has no request object verification key configured")]
    VerificationKeyMissing(String),

    #[error(transparent)]
    Jose(#[from] RequestObjectError),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ClientRegistryStateError {
    #[error("client registry state lock poisoned: {0}")]
    LockPoisoned(&'static str),
}

fn log_client_registry_state_error(operation: &'static str, error: &ClientRegistryStateError) {
    tracing::error!(
        %error,
        operation,
        "client registry state operation failed"
    );
}

#[derive(Clone)]
pub struct ClientRegistry {
    clients: Arc<RwLock<HashMap<String, RegisteredClient>>>,
    client_secret_credentials: Arc<RwLock<HashMap<String, Vec<ClientSecretCredential>>>>,
    runtime_snapshot_fingerprint: Arc<RwLock<Option<String>>>,
    jwt_replay_store: Arc<dyn ReplayStore>,
    client_assertion_policy: ClientAssertionRuntimePolicy,
    jwks_policy: JwksRuntimePolicy,
    jwks_state: JwksRuntimeState,
}

pub(crate) struct ClientRegistryClientProjectionWriteGuard<'a> {
    clients: RwLockWriteGuard<'a, HashMap<String, RegisteredClient>>,
    client_secret_credentials: RwLockWriteGuard<'a, HashMap<String, Vec<ClientSecretCredential>>>,
}

pub(crate) struct ClientRegistryRuntimeProjectionWriteGuard<'a> {
    client_projection: ClientRegistryClientProjectionWriteGuard<'a>,
    runtime_snapshot_fingerprint: RwLockWriteGuard<'a, Option<String>>,
}

#[cfg(test)]
fn test_clients_allowed_by_build(allowed_by_build: bool) -> Result<(), ConfigError> {
    if allowed_by_build {
        return Ok(());
    }
    Err(ConfigError::InvalidValue {
        key: SEEDED_TEST_CLIENTS_BUILD_GUARD.to_string(),
        value: "true".to_string(),
        reason: "seeded test clients are only available in tests".to_string(),
    })
}

#[cfg(any(test, kani))]
static JWKS_RUNTIME_STATE: std::sync::LazyLock<JwksRuntimeState> =
    std::sync::LazyLock::new(JwksRuntimeState::default);

#[cfg(any(test, kani))]
fn jwks_runtime_state() -> &'static JwksRuntimeState {
    &JWKS_RUNTIME_STATE
}

fn sha256_hex(data: &[u8]) -> String {
    aegaeon_crypto::hash::sha256_hex(data)
}

#[cfg(test)]
fn env_flag(key: &str, default: bool) -> bool {
    try_env_flag(key, default).unwrap_or_else(|err| {
        warn!(target: "jwks", error = %err, "invalid JWKS boolean override ignored");
        default
    })
}

fn shared_kid_reuse_changed_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    new_map: &HashMap<String, String>,
) -> Result<bool, JwksSharedStateError> {
    if policy.allow_kid_reuse {
        return Ok(false);
    }
    match &state.inner.shared_state {
        #[cfg(any(test, kani))]
        JwksSharedRuntimeState::InMemory => Ok(false),
        JwksSharedRuntimeState::Redis(redis_state) => {
            let result = redis_state.record_kid_fingerprints(policy, uri, new_map);
            if result.is_err() {
                record_jwks_shared_runtime_state_failure("kid_fingerprints", uri);
            }
            result
        }
    }
}

fn maybe_log_event(policy: &JwksRuntimePolicy, outcome: &str, uri: &str, detail: Option<&str>) {
    let sample = policy.log_sample_percent_for(outcome);
    if sample == 0 {
        return;
    }
    if should_sample(sample) {
        let uri_hash = &sha256_hex(uri.as_bytes())[0..8];
        match outcome {
            "200" => debug!(target: "jwks_event", uri_hash=%uri_hash, outcome="200"),
            "304" => debug!(target: "jwks_event", uri_hash=%uri_hash, outcome="304"),
            "failure" => {
                warn!(target: "jwks_event", uri_hash=%uri_hash, outcome="failure", reason=?detail);
            }
            "error" => warn!(target: "jwks_event", uri_hash=%uri_hash, outcome="error"),
            other => debug!(target: "jwks_event", uri_hash=%uri_hash, outcome=%other),
        }
    }
}

fn should_sample(percent: u8) -> bool {
    let mut b = [0u8; 1];
    let _ = aegaeon_crypto::rand::fill_random(&mut b);
    (b[0] % 100) < percent
}

#[cfg(test)]
mod jwks_helpers_tests;
