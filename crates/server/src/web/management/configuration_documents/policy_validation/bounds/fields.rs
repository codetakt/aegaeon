use crate::management::types::PolicyDocument;

type NumericPolicyField = (&'static str, u32);

mod federation;
mod jwks;
mod protocol;
mod session;
mod token;

pub(super) fn sql_integer_fields(
    policy: &PolicyDocument,
) -> impl Iterator<Item = NumericPolicyField> {
    protocol::protocol_and_replay_fields(policy)
        .into_iter()
        .chain(jwks::jwks_fields(policy))
        .chain(token::token_and_oidc_fields(policy))
        .chain(session::session_and_upstream_fields(policy))
        .chain(federation::federation_fields(policy))
}
