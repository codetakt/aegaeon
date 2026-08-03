mod algorithms;
mod decode;
mod errors;
mod signature;
mod validation;

pub(super) use decode::{decode_upstream_id_token, UpstreamIdTokenDecodeInput};
pub(super) use errors::{
    refreshed_upstream_id_token_signature_failure, UpstreamIdTokenSignatureError,
};
pub(super) use signature::{verify_compact_jwt_payload_with_key, verify_upstream_id_token_claims};
pub(super) use validation::{validate_upstream_id_token, UpstreamIdTokenValidationInput};

#[cfg(test)]
pub(super) use algorithms::jwt_alg_name;
