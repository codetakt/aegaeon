use super::super::jwks_circuit::circuit_on_failure_with_state;
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::{maybe_log_event, metrics, JwksRuntimePolicy};

pub(super) fn record_jwks_refresh_internal_failure_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    reason: &'static str,
    start: std::time::Instant,
) {
    metrics::record_jwks_http_error(policy, uri_hash, reason, start.elapsed());
    maybe_log_event(policy, "error", uri, Some(reason));
    circuit_on_failure_with_state(state, policy, uri);
}
