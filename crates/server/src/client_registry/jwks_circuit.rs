use tracing::{info, warn};

use super::jwks_runtime_state::{CircuitPhase, CircuitState, JwksRuntimeState};
use super::{metrics, sha256_hex, JwksRuntimePolicy};

fn circuit_set_gauge(uri: &str, phase: CircuitPhase) {
    let uri_hash = &sha256_hex(uri.as_bytes())[0..8];
    let active_state = match phase {
        CircuitPhase::Open => "open",
        CircuitPhase::HalfOpen => "half_open",
        CircuitPhase::Closed => "closed",
    };
    metrics::set_jwks_circuit_state(uri_hash, active_state);
}

pub(super) fn record_jwks_shared_runtime_state_failure(operation: &'static str, uri: &str) {
    let uri_hash = &sha256_hex(uri.as_bytes())[0..8];
    metrics::record_jwks_shared_runtime_state_failure(operation, uri_hash);
}

pub(super) fn record_jwks_in_memory_runtime_state_failure(
    operation: &'static str,
    uri: &str,
    error: impl std::fmt::Display,
) {
    record_jwks_shared_runtime_state_failure(operation, uri);
    warn!(
        target: "jwks",
        error = %error,
        "JWKS in-memory runtime state lock failed"
    );
}

fn circuit_transition_inner(uri: &str, st: &mut CircuitState, new_phase: CircuitPhase) {
    if st.phase != new_phase {
        let uri_hash = &sha256_hex(uri.as_bytes())[0..8];
        match new_phase {
            CircuitPhase::Open => {
                warn!(target: "jwks_circuit", uri_hash=%uri_hash, "circuit opened");
            }
            CircuitPhase::HalfOpen => {
                info!(target: "jwks_circuit", uri_hash=%uri_hash, "circuit half-open (probe)");
            }
            CircuitPhase::Closed => {
                info!(target: "jwks_circuit", uri_hash=%uri_hash, "circuit closed");
            }
        }
        st.phase = new_phase;
        st.probe_in_flight = false;
        if matches!(new_phase, CircuitPhase::Open) {
            st.opened_at = Some(std::time::Instant::now());
        } else {
            st.opened_at = None;
        }
    }
    circuit_set_gauge(uri, st.phase);
}

#[cfg(any(test, kani))]
pub(super) fn circuit_on_success(uri: &str) {
    circuit_on_success_with_state(
        super::jwks_runtime_state(),
        &JwksRuntimePolicy::default(),
        uri,
    );
}

pub(super) fn circuit_on_success_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
) {
    if let Some(redis_state) = state.redis_shared_state() {
        match redis_state.circuit_on_success(policy, uri) {
            Ok(()) => {
                circuit_set_gauge(uri, CircuitPhase::Closed);
            }
            Err(err) => {
                record_jwks_shared_runtime_state_failure("circuit_success", uri);
                warn!(
                    target: "jwks",
                    error = %err,
                    "failed to update shared JWKS circuit success state"
                );
            }
        }
        return;
    }
    match state.inner.coordination.circuits.lock() {
        Ok(mut map) => {
            let st = map.entry(uri.to_string()).or_default();
            st.consecutive_failures = 0;
            if st.phase == CircuitPhase::Closed {
                circuit_set_gauge(uri, CircuitPhase::Closed);
            } else {
                circuit_transition_inner(uri, st, CircuitPhase::Closed);
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("circuit_success_lock", uri, err);
        }
    }
}

#[cfg(any(test, kani))]
pub(super) fn circuit_on_failure(policy: &JwksRuntimePolicy, uri: &str) {
    circuit_on_failure_with_state(super::jwks_runtime_state(), policy, uri);
}

pub(super) fn circuit_on_failure_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
) {
    if let Some(redis_state) = state.redis_shared_state() {
        match redis_state.circuit_on_failure(policy, uri) {
            Ok(phase) => {
                circuit_set_gauge(uri, phase);
            }
            Err(err) => {
                record_jwks_shared_runtime_state_failure("circuit_failure", uri);
                warn!(
                    target: "jwks",
                    error = %err,
                    "failed to update shared JWKS circuit failure state"
                );
            }
        }
        return;
    }
    match state.inner.coordination.circuits.lock() {
        Ok(mut map) => {
            let st = map.entry(uri.to_string()).or_default();
            if st.phase == CircuitPhase::HalfOpen {
                st.consecutive_failures = st.consecutive_failures.saturating_add(1);
                circuit_transition_inner(uri, st, CircuitPhase::Open);
                return;
            }
            st.consecutive_failures = st.consecutive_failures.saturating_add(1);
            let threshold = policy.circuit_open_fails;
            if st.consecutive_failures >= threshold {
                if st.phase == CircuitPhase::Open {
                    circuit_set_gauge(uri, st.phase);
                } else {
                    circuit_transition_inner(uri, st, CircuitPhase::Open);
                }
            } else {
                circuit_set_gauge(uri, st.phase);
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("circuit_failure_lock", uri, err);
            circuit_set_gauge(uri, CircuitPhase::Open);
        }
    }
}

#[cfg(any(test, kani))]
pub(super) fn circuit_phase(uri: &str) -> CircuitPhase {
    circuit_phase_with_state(super::jwks_runtime_state(), uri)
}

#[cfg(any(test, kani))]
pub(super) fn circuit_phase_with_state(state: &JwksRuntimeState, uri: &str) -> CircuitPhase {
    if let Some(redis_state) = state.redis_shared_state() {
        return match redis_state.circuit_phase(uri) {
            Ok(phase) => phase,
            Err(err) => {
                record_jwks_shared_runtime_state_failure("circuit_phase", uri);
                warn!(
                    target: "jwks",
                    error = %err,
                    "failed to read shared JWKS circuit phase"
                );
                CircuitPhase::Open
            }
        };
    }
    match state.inner.coordination.circuits.lock() {
        Ok(map) => {
            if let Some(st) = map.get(uri) {
                return st.phase;
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("circuit_phase_lock", uri, err);
            circuit_set_gauge(uri, CircuitPhase::Open);
            return CircuitPhase::Open;
        }
    }
    CircuitPhase::Closed
}

#[cfg(any(test, kani))]
pub(super) fn circuit_allow_fetch(policy: &JwksRuntimePolicy, uri: &str) -> bool {
    circuit_allow_fetch_with_state(super::jwks_runtime_state(), policy, uri)
}

pub(super) fn circuit_allow_fetch_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
) -> bool {
    if let Some(redis_state) = state.redis_shared_state() {
        return match redis_state.circuit_allow_fetch(policy, uri) {
            Ok(CircuitPhase::Closed) => {
                circuit_set_gauge(uri, CircuitPhase::Closed);
                true
            }
            Ok(CircuitPhase::HalfOpen) => {
                circuit_set_gauge(uri, CircuitPhase::HalfOpen);
                true
            }
            Ok(CircuitPhase::Open) => {
                circuit_set_gauge(uri, CircuitPhase::Open);
                false
            }
            Err(err) => {
                record_jwks_shared_runtime_state_failure("circuit_allow_fetch", uri);
                warn!(
                    target: "jwks",
                    error = %err,
                    "failed to evaluate shared JWKS circuit state"
                );
                circuit_set_gauge(uri, CircuitPhase::Open);
                false
            }
        };
    }
    match state.inner.coordination.circuits.lock() {
        Ok(mut map) => {
            let st = map.entry(uri.to_string()).or_default();
            match st.phase {
                CircuitPhase::Closed => {
                    circuit_set_gauge(uri, CircuitPhase::Closed);
                    true
                }
                CircuitPhase::Open => {
                    if let Some(ts) = st.opened_at {
                        if ts.elapsed().as_secs() >= policy.circuit_reset_secs {
                            circuit_transition_inner(uri, st, CircuitPhase::HalfOpen);
                            st.probe_in_flight = true;
                            true
                        } else {
                            circuit_set_gauge(uri, CircuitPhase::Open);
                            false
                        }
                    } else {
                        circuit_set_gauge(uri, CircuitPhase::Open);
                        false
                    }
                }
                CircuitPhase::HalfOpen => {
                    circuit_set_gauge(uri, CircuitPhase::HalfOpen);
                    if st.probe_in_flight {
                        false
                    } else {
                        st.probe_in_flight = true;
                        true
                    }
                }
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("circuit_allow_fetch_lock", uri, err);
            circuit_set_gauge(uri, CircuitPhase::Open);
            false
        }
    }
}
