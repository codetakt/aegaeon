use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

pub const DEFAULT_UPSTREAM_METADATA_CACHE_TTL_SECS: u64 = 300;
pub const MAX_UPSTREAM_METADATA_CACHE_TTL_SECS: u64 = 86_400;
pub const DEFAULT_UPSTREAM_METADATA_CACHE_MAX_ENTRIES: usize = 4096;
pub const MAX_UPSTREAM_METADATA_CACHE_MAX_ENTRIES: u32 = 1_000_000;

mod auth_store;
mod client_secret;
mod federation_policy;
mod identity;
mod metadata_cache;
mod store;
mod types;

pub use client_secret::{
    open_upstream_client_secret, seal_upstream_client_secret,
    upstream_client_auth_method_supported, upstream_client_auth_method_uses_secret,
    UpstreamClientSecretEnvelopeError,
};
pub use federation_policy::{
    email_allowed_by_domain_allowlist, extract_email_domain, filter_downstream_custom_claims,
    merge_upstream_custom_claims, parse_upstream_attribute_mappings,
    parse_upstream_claim_release_policy, parse_upstream_jit_provisioning_policy,
    parse_upstream_logout_policy, project_upstream_attribute_mappings,
};
pub use identity::upstream_subject_link_hash;
pub use metadata_cache::NonAuthoritativeMetadataCache;
pub use store::UpstreamAuthStore;
pub use types::*;

#[cfg(test)]
use auth_store::RedisUpstreamAuthRequest;
#[cfg(test)]
use client_secret::{KEY_ENCRYPTION_KEY_ENV, UPSTREAM_CLIENT_SECRET_ENVELOPE_PREFIX};
#[cfg(test)]
use store::upstream_auth_request_is_fresh_at;

pub const fn valid_upstream_metadata_cache_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_UPSTREAM_METADATA_CACHE_TTL_SECS
}

pub const fn valid_upstream_metadata_cache_max_entries(value: u32) -> bool {
    value > 0 && value <= MAX_UPSTREAM_METADATA_CACHE_MAX_ENTRIES
}

pub fn normalize_upstream_outbound_allowed_domains(
    domains: &[String],
) -> Result<Vec<String>, String> {
    crate::federation::normalize_federation_outbound_allowed_domains(domains).map_err(|err| {
        err.to_string()
            .replace("federation outbound", "upstream outbound")
    })
}

#[must_use]
pub fn random_token(bytes_len: usize) -> String {
    aegaeon_crypto::rand::random_base64url(bytes_len.max(16))
}

#[must_use]
pub fn pkce_challenge(verifier: &str) -> String {
    let digest = aegaeon_crypto::hash::sha256_digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests;
