mod allowlists;
mod capacity;
mod credential_lifecycle;
mod jwks;
mod jwt_dcr_ssa;
mod oidc_mtls_federation;
mod protocol;
mod structural;

use super::super::super::super::i32_from_u32_field;
use crate::management::types::PolicyDocument;
use axum::response::Response;
use sqlx::{postgres::PgArguments, query::Query, Postgres};

type PolicyUpdateQuery<'q> = Query<'q, Postgres, PgArguments>;

pub(super) fn bind_policy_update_fields<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    let query = protocol::bind_protocol_and_client_policy(query, policy, request_id)?;
    let query = jwks::bind_jwks_policy(query, policy, request_id)?;
    let query = jwt_dcr_ssa::bind_jwt_dcr_and_ssa_policy(query, policy, request_id)?;
    let query =
        oidc_mtls_federation::bind_oidc_mtls_and_federation_policy(query, policy, request_id)?;
    let query = allowlists::bind_allowlists_ttls_and_acr_policy(query, policy, request_id)?;
    let query = structural::bind_structural_self_check_policy(query, policy, request_id)?;
    let query = capacity::bind_cache_capacity_policy(query, policy, request_id)?;
    credential_lifecycle::bind_credential_lifecycle_policy(query, policy, request_id)
}
