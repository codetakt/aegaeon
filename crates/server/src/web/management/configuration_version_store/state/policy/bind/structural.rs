use super::{i32_from_u32_field, PolicyUpdateQuery};
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(super) fn bind_structural_self_check_policy<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    Ok(query
        .bind(policy.dcr_everparse_runtime_enabled)
        .bind(policy.request_object_everparse_runtime_enabled)
        .bind(i32_from_u32_field(
            "jose_header_max_len",
            policy.jose_header_max_len,
            request_id,
        )?))
}
