use axum::response::Response;

use crate::config::{
    valid_stepup_challenge_ttl_secs, valid_upstream_auth_ttl_secs,
    valid_upstream_logout_relay_ttl_secs,
};
use crate::federation::{valid_federation_cache_max_entries, valid_federation_cache_ttl_secs};
use crate::management::types::PolicyDocument;
use crate::upstream::{
    valid_upstream_metadata_cache_max_entries, valid_upstream_metadata_cache_ttl_secs,
};

use super::invalid_request;

pub(in crate::web::management::configuration_documents::policy_validation) fn validate_upstream_and_federation_ranges(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    if !valid_stepup_challenge_ttl_secs(u64::from(policy.stepup_challenge_ttl_seconds)) {
        return Err(invalid_request(
            "Step-up challenge TTL exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_upstream_auth_ttl_secs(u64::from(policy.upstream_auth_ttl_seconds)) {
        return Err(invalid_request(
            "Upstream auth state TTL exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_upstream_logout_relay_ttl_secs(u64::from(policy.upstream_logout_relay_ttl_seconds)) {
        return Err(invalid_request(
            "Upstream logout relay TTL exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_upstream_metadata_cache_ttl_secs(u64::from(
        policy.upstream_discovery_cache_ttl_seconds,
    )) || !valid_upstream_metadata_cache_ttl_secs(u64::from(
        policy.upstream_jwks_cache_ttl_seconds,
    )) || !valid_upstream_metadata_cache_max_entries(policy.upstream_discovery_cache_max_entries)
        || !valid_upstream_metadata_cache_max_entries(policy.upstream_jwks_cache_max_entries)
    {
        return Err(invalid_request(
            "Upstream metadata cache TTLs and capacity exceed the supported policy range",
            request_id,
        ));
    }
    if !valid_federation_cache_ttl_secs(u64::from(policy.federation_entity_cache_ttl_seconds))
        || !valid_federation_cache_ttl_secs(u64::from(
            policy.federation_trust_chain_cache_ttl_seconds,
        ))
        || !valid_federation_cache_max_entries(policy.federation_cache_max_entries)
    {
        return Err(invalid_request(
            "Federation cache TTLs and capacity must be positive and within supported bounds",
            request_id,
        ));
    }
    if crate::federation::normalize_federation_outbound_allowed_domains(
        &policy.federation_outbound_allowed_domains,
    )
    .is_err()
    {
        return Err(invalid_request(
            "Federation outbound allowed domains must be unique plain DNS domains",
            request_id,
        ));
    }
    if crate::upstream::normalize_upstream_outbound_allowed_domains(
        &policy.upstream_outbound_allowed_domains,
    )
    .is_err()
    {
        return Err(invalid_request(
            "Upstream outbound allowed domains must be unique plain DNS domains",
            request_id,
        ));
    }

    Ok(())
}
