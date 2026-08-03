use std::time::Duration;

pub const MAX_FEDERATION_CACHE_TTL_SECS: u64 = 24 * 60 * 60;
pub const DEFAULT_FEDERATION_ENTITY_CACHE_TTL_SECS: u64 = 30 * 60;
pub const DEFAULT_FEDERATION_TRUST_CHAIN_CACHE_TTL_SECS: u64 = 60 * 60;
pub const DEFAULT_FEDERATION_CACHE_MAX_ENTRIES: usize = 1000;
pub const MAX_FEDERATION_CACHE_MAX_ENTRIES: u32 = 1_000_000;

pub const fn valid_federation_cache_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_FEDERATION_CACHE_TTL_SECS
}

pub const fn valid_federation_cache_max_entries(value: u32) -> bool {
    value > 0 && value <= MAX_FEDERATION_CACHE_MAX_ENTRIES
}

/// Configuration for federation cache TTLs and capacity.
#[derive(Debug, Clone)]
pub struct FederationCacheConfig {
    /// TTL for cached entity configurations (default: 30 minutes).
    pub entity_cache_ttl: Duration,
    /// TTL for cached resolved trust chains (default: 60 minutes).
    pub trust_chain_cache_ttl: Duration,
    /// Maximum number of entries per environment for entity and trust-chain caches.
    pub cache_max_entries: usize,
    /// Optional outbound domain allowlist for Federation metadata fetches.
    pub outbound_allowed_domains: Vec<String>,
}

impl Default for FederationCacheConfig {
    fn default() -> Self {
        Self {
            entity_cache_ttl: Duration::from_secs(DEFAULT_FEDERATION_ENTITY_CACHE_TTL_SECS),
            trust_chain_cache_ttl: Duration::from_secs(
                DEFAULT_FEDERATION_TRUST_CHAIN_CACHE_TTL_SECS,
            ),
            cache_max_entries: DEFAULT_FEDERATION_CACHE_MAX_ENTRIES,
            outbound_allowed_domains: Vec::new(),
        }
    }
}

impl FederationCacheConfig {
    pub fn try_from_management_policy(
        policy: &crate::management::types::PolicyDocument,
    ) -> Result<Self, crate::config::ConfigError> {
        let entity_secs = u64::from(policy.federation_entity_cache_ttl_seconds);
        if !valid_federation_cache_ttl_secs(entity_secs) {
            return Err(crate::config::ConfigError::InvalidNumberRange {
                key: "federation_entity_cache_ttl_seconds".to_string(),
                value: entity_secs.to_string(),
                expectation: "a value in 1..=86400 seconds".to_string(),
            });
        }

        let chain_secs = u64::from(policy.federation_trust_chain_cache_ttl_seconds);
        if !valid_federation_cache_ttl_secs(chain_secs) {
            return Err(crate::config::ConfigError::InvalidNumberRange {
                key: "federation_trust_chain_cache_ttl_seconds".to_string(),
                value: chain_secs.to_string(),
                expectation: "a value in 1..=86400 seconds".to_string(),
            });
        }

        if !valid_federation_cache_max_entries(policy.federation_cache_max_entries) {
            return Err(crate::config::ConfigError::InvalidNumberRange {
                key: "federation_cache_max_entries".to_string(),
                value: policy.federation_cache_max_entries.to_string(),
                expectation: "a value in 1..=1000000 entries".to_string(),
            });
        }

        Ok(Self {
            entity_cache_ttl: Duration::from_secs(entity_secs),
            trust_chain_cache_ttl: Duration::from_secs(chain_secs),
            cache_max_entries: policy.federation_cache_max_entries as usize,
            outbound_allowed_domains:
                crate::federation::normalize_federation_outbound_allowed_domains(
                    &policy.federation_outbound_allowed_domains,
                )
                .map_err(|error| crate::config::ConfigError::InvalidValue {
                    key: "federation_outbound_allowed_domains".to_string(),
                    value: policy.federation_outbound_allowed_domains.join(","),
                    reason: error.to_string(),
                })?,
        })
    }
}
