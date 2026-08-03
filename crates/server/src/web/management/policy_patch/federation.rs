use crate::management::types::{PolicyDocument, PolicyPatchRequest};

fn normalize_domain_allowlist(domains: &[String]) -> Vec<String> {
    domains.iter().fold(Vec::new(), |mut normalized, domain| {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !domain.is_empty() && !normalized.iter().any(|existing| existing == &domain) {
            normalized.push(domain);
        }
        normalized
    })
}

pub(super) fn apply_federation_policy_patch(
    policy: &mut PolicyDocument,
    patch: &PolicyPatchRequest,
) {
    if let Some(value) = patch.federation_outbound_allowed_domains.as_ref() {
        policy.federation_outbound_allowed_domains = normalize_domain_allowlist(value);
    }
    if let Some(value) = patch.upstream_outbound_allowed_domains.as_ref() {
        policy.upstream_outbound_allowed_domains = normalize_domain_allowlist(value);
    }
    if let Some(value) = patch.federation_entity_cache_ttl_seconds {
        policy.federation_entity_cache_ttl_seconds = value;
    }
    if let Some(value) = patch.federation_trust_chain_cache_ttl_seconds {
        policy.federation_trust_chain_cache_ttl_seconds = value;
    }
    if let Some(value) = patch.federation_cache_max_entries {
        policy.federation_cache_max_entries = value;
    }
}
