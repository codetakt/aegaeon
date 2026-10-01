use super::jwks_runtime_state::JwksRuntimeState;
use super::jwks_types::FetchedJwks;
use super::{sha256_hex, JwksRuntimePolicy};

pub(super) struct JwksFetchContext<'a> {
    pub(super) state: &'a JwksRuntimeState,
    pub(super) policy: &'a JwksRuntimePolicy,
    pub(super) uri: &'a str,
    pub(super) skew_secs: u64,
    uri_hash: String,
}

#[derive(Default)]
pub(super) struct MemoryCacheProbe {
    pub(super) hit: Option<FetchedJwks>,
    pub(super) authoritative_failure: bool,
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
            skew_secs: policy.refresh_skew_secs,
            uri_hash: sha256_hex(uri.as_bytes())[0..8].to_string(),
        }
    }

    pub(super) fn uri_hash(&self) -> &str {
        &self.uri_hash
    }
}
