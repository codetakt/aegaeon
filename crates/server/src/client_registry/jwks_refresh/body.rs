#[cfg(test)]
use super::super::jwks_runtime_state;
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::jwks_types::FetchedJwks;
use super::super::JwksRuntimePolicy;
use super::failure::record_jwks_refresh_internal_failure_with_state;
use crate::util::deserialize_json_without_duplicate_object_keys;
use tracing::warn;

#[cfg(test)]
pub(in crate::client_registry) fn decode_fetched_jwks_body(
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    bytes: &[u8],
    start: std::time::Instant,
) -> Option<FetchedJwks> {
    decode_fetched_jwks_body_with_state(jwks_runtime_state(), policy, uri, uri_hash, bytes, start)
}

pub(super) fn decode_fetched_jwks_body_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    bytes: &[u8],
    start: std::time::Instant,
) -> Option<FetchedJwks> {
    match deserialize_json_without_duplicate_object_keys(bytes) {
        Ok(jwks) => Some(jwks),
        Err(err) => {
            warn!(target: "jwks", uri_hash=%uri_hash, error=%err, "jwks json parse failed");
            record_jwks_refresh_internal_failure_with_state(
                state,
                policy,
                uri,
                uri_hash,
                "json_parse",
                start,
            );
            None
        }
    }
}
