use super::errors::{upstream_id_token_signature_failure, UpstreamIdTokenDecodeError};
use super::signature::verify_upstream_id_token_claims;
use super::validation::{validate_upstream_id_token, UpstreamIdTokenValidationInput};
use aegaeon_jose::jwk::JwkSet;

use crate::oidc::{IdToken, OidcDiscovery};
use crate::upstream::UpstreamAuthRequest;

#[derive(Clone, Copy)]
pub(in crate::web) struct UpstreamIdTokenDecodeInput<'a> {
    pub(in crate::web) token: &'a str,
    pub(in crate::web) jwks: &'a JwkSet,
    pub(in crate::web) discovery: &'a OidcDiscovery,
    pub(in crate::web) request: &'a UpstreamAuthRequest,
    pub(in crate::web) access_token: Option<&'a str>,
    pub(in crate::web) code: &'a str,
    pub(in crate::web) jwt_leeway_secs: u64,
    pub(in crate::web) jose_header_max_len: usize,
}

pub(in crate::web) fn decode_upstream_id_token(
    input: UpstreamIdTokenDecodeInput<'_>,
) -> Result<IdToken, UpstreamIdTokenDecodeError> {
    let (claims, alg_name) = verify_upstream_id_token_claims(
        input.token,
        input.jwks,
        input.discovery,
        input.jose_header_max_len,
    )
    .map_err(upstream_id_token_signature_failure)?;

    let id_token = IdToken {
        claims,
        signing_alg: alg_name.to_string(),
    };

    validate_upstream_id_token(
        &id_token,
        &UpstreamIdTokenValidationInput {
            client_id: &input.request.client_id,
            issuer: &input.request.issuer,
            expected_nonce: Some(input.request.nonce.as_str()),
            max_age: input.request.max_age,
            access_token: input.access_token,
            code: Some(input.code),
            requested_acr: input.request.acr.as_deref(),
            jwt_leeway_secs: input.jwt_leeway_secs,
        },
    )
    .map_err(UpstreamIdTokenDecodeError::bad_gateway)?;

    Ok(id_token)
}
