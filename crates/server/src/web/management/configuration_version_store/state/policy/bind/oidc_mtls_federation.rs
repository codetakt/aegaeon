use super::{i32_from_u32_field, PolicyUpdateQuery};
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(super) fn bind_oidc_mtls_and_federation_policy<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    Ok(query
        .bind(policy.oidc_enabled)
        .bind(policy.oidc_enable_discovery)
        .bind(policy.oidc_enable_userinfo)
        .bind(policy.oidc_enable_logout)
        .bind(policy.oidc_enable_backchannel_logout)
        .bind(i32_from_u32_field(
            "oidc_logout_session_ttl_seconds",
            policy.oidc_logout_session_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "oidc_backchannel_logout_timeout_seconds",
            policy.oidc_backchannel_logout_timeout_seconds,
            request_id,
        )?)
        .bind(policy.oidc_require_nonce)
        .bind(policy.mtls_enabled)
        .bind(policy.mtls_base_url.clone())
        .bind(policy.mtls_alias_par_enabled)
        .bind(policy.federation_outbound_allowed_domains.clone())
        .bind(policy.upstream_outbound_allowed_domains.clone())
        .bind(i32_from_u32_field(
            "federation_entity_cache_ttl_seconds",
            policy.federation_entity_cache_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "federation_trust_chain_cache_ttl_seconds",
            policy.federation_trust_chain_cache_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "federation_cache_max_entries",
            policy.federation_cache_max_entries,
            request_id,
        )?))
}
