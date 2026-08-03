use super::decoder::PolicyRowDecoder;
use axum::response::Response;

pub(super) struct FederationPolicyFields {
    pub(super) federation_outbound_allowed_domains: Vec<String>,
    pub(super) upstream_outbound_allowed_domains: Vec<String>,
    pub(super) federation_entity_cache_ttl_seconds: u32,
    pub(super) federation_trust_chain_cache_ttl_seconds: u32,
    pub(super) federation_cache_max_entries: u32,
}

pub(super) fn read_federation_policy_fields(
    decoder: &PolicyRowDecoder<'_>,
) -> Result<FederationPolicyFields, Response> {
    Ok(FederationPolicyFields {
        federation_outbound_allowed_domains: decoder
            .vec_field("federation_outbound_allowed_domains")?,
        upstream_outbound_allowed_domains: decoder
            .vec_field("upstream_outbound_allowed_domains")?,
        federation_entity_cache_ttl_seconds: decoder
            .seconds_field("federation_entity_cache_ttl_seconds", 1)?,
        federation_trust_chain_cache_ttl_seconds: decoder
            .seconds_field("federation_trust_chain_cache_ttl_seconds", 1)?,
        federation_cache_max_entries: decoder.u32_field("federation_cache_max_entries", 1)?,
    })
}
