use super::jwks_cache_control::parse_cache_control;
use super::jwks_circuit::{
    circuit_allow_fetch, circuit_on_failure, circuit_on_success, circuit_phase,
};
use super::jwks_runtime_state::CircuitPhase;
use super::{jwks_runtime_state, JwksRuntimePolicy};

// Kani-only test shims to exercise circuit behavior without network.
pub fn __circuit_reset(uri: &str) {
    if let Ok(mut map) = jwks_runtime_state().inner.coordination.circuits.lock() {
        map.remove(uri);
    }
}

pub fn __circuit_on_failure(uri: &str) {
    circuit_on_failure(&JwksRuntimePolicy::default(), uri)
}

pub fn __circuit_on_success(uri: &str) {
    circuit_on_success(uri)
}

pub fn __circuit_force_half_open(uri: &str) {
    if let Ok(mut map) = jwks_runtime_state().inner.coordination.circuits.lock() {
        let st = map.entry(uri.to_string()).or_default();
        st.phase = CircuitPhase::HalfOpen;
        st.opened_at = None;
        st.probe_in_flight = false;
    }
}

pub fn __circuit_allow_fetch(uri: &str) -> bool {
    circuit_allow_fetch(&JwksRuntimePolicy::default(), uri)
}

pub fn __circuit_phase(uri: &str) -> u8 {
    match circuit_phase(uri) {
        CircuitPhase::Closed => 0,
        CircuitPhase::Open => 1,
        CircuitPhase::HalfOpen => 2,
    }
}

pub fn __parse_cache_control_val(s: &str) -> Option<u64> {
    use reqwest::header::{HeaderMap, HeaderValue, CACHE_CONTROL};
    let mut h = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(s) {
        h.insert(CACHE_CONTROL, v);
    }
    parse_cache_control(&h)
}

pub fn __sha256_hex(data: &[u8]) -> String {
    aegaeon_crypto::hash::sha256_hex(data)
}

const MAX_JWKS_KEYS: usize = 4;

const KANI_KTY_EC: u8 = 1;
const KANI_KTY_RSA: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaniFetchedJwk {
    pub kty: u8,
    pub kid: Option<u8>,
    pub n: Option<u8>,
    pub e: Option<u8>,
    pub x: Option<u8>,
    pub y: Option<u8>,
}

fn __kani_fetched_jwk_signature_capable(jwk: &KaniFetchedJwk) -> bool {
    match jwk.kty {
        KANI_KTY_RSA => jwk.n.is_some() && jwk.e.is_some(),
        KANI_KTY_EC => jwk.x.is_some() && jwk.y.is_some(),
        _ => false,
    }
}

pub fn __has_duplicate_kid(keys: &[Option<u8>]) -> bool {
    let mut seen = [None; MAX_JWKS_KEYS];
    for kid in keys.iter().flatten() {
        if seen.contains(&Some(*kid)) {
            return true;
        }
        if let Some(slot) = seen.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(*kid);
        }
    }
    false
}

pub fn __kid_reuse_changed(prev_entries: &[(u8, u8)], new_entries: &[(u8, u8)]) -> bool {
    for &(kid, new_fp) in new_entries {
        if let Some((_, old_fp)) = prev_entries.iter().find(|(existing, _)| *existing == kid) {
            if *old_fp != new_fp {
                return true;
            }
        }
    }
    false
}

pub fn __select_jwk_tuple(keys: &[KaniFetchedJwk], kid: Option<u8>) -> Option<KaniFetchedJwk> {
    if let Some(target) = kid {
        for jwk in keys {
            if jwk.kid == Some(target) && __kani_fetched_jwk_signature_capable(jwk) {
                return Some(*jwk);
            }
        }
        return None;
    }
    let mut selected = None;
    for jwk in keys {
        if __kani_fetched_jwk_signature_capable(jwk) {
            if selected.is_some() {
                return None;
            }
            selected = Some(*jwk);
        }
    }
    selected
}
