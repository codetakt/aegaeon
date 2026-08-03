use super::{i32_from_u32_field, PolicyUpdateQuery};
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(super) fn bind_cache_capacity_policy<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    Ok(query
        .bind(i32_from_u32_field(
            "jwks_local_cache_max_entries",
            policy.jwks_local_cache_max_entries,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "upstream_discovery_cache_max_entries",
            policy.upstream_discovery_cache_max_entries,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "upstream_jwks_cache_max_entries",
            policy.upstream_jwks_cache_max_entries,
            request_id,
        )?))
}
