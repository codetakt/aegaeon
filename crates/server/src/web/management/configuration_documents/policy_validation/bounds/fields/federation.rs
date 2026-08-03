use crate::management::types::PolicyDocument;

use super::NumericPolicyField;

pub(super) fn federation_fields(policy: &PolicyDocument) -> [NumericPolicyField; 3] {
    [
        (
            "federation_entity_cache_ttl_seconds",
            policy.federation_entity_cache_ttl_seconds,
        ),
        (
            "federation_trust_chain_cache_ttl_seconds",
            policy.federation_trust_chain_cache_ttl_seconds,
        ),
        (
            "federation_cache_max_entries",
            policy.federation_cache_max_entries,
        ),
    ]
}
