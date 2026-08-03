use super::jwks_runtime_state::JwksRuntimeState;
use super::jwks_types::FetchedJwks;
use super::{sha256_hex, JwksRuntimePolicy};
use std::time::Instant;

pub(super) struct JwksFetchContext<'a> {
    pub(super) state: &'a JwksRuntimeState,
    pub(super) policy: &'a JwksRuntimePolicy,
    pub(super) uri: &'a str,
    pub(super) now: Instant,
    pub(super) ttl_default: u64,
    pub(super) skew_secs: u64,
    uri_hash: String,
}

#[derive(Default)]
pub(super) struct MemoryCacheProbe {
    pub(super) cached_etag: Option<String>,
    pub(super) cached_last_mod: Option<String>,
    pub(super) hit: Option<FetchedJwks>,
}

impl<'a> JwksFetchContext<'a> {
    pub(super) fn new(
        state: &'a JwksRuntimeState,
        policy: &'a JwksRuntimePolicy,
        uri: &'a str,
    ) -> Self {
        Self {
            state,
            policy,
            uri,
            now: Instant::now(),
            ttl_default: policy.cache_ttl_secs,
            skew_secs: policy.refresh_skew_secs,
            uri_hash: sha256_hex(uri.as_bytes())[0..8].to_string(),
        }
    }

    pub(super) fn uri_hash(&self) -> &str {
        &self.uri_hash
    }
}
