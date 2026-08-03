use aegaeon_jose::{
    algorithms::CryptoProfile, verify_request_object, verify_request_object_ps256_promoted,
    verify_request_object_rs256_promoted, RequestObjectError, RequestObjectVerification,
};

use super::super::request_object_keys::{
    resolve_promoted_rsa_verification_key_with_state, resolve_request_object_key_with_state,
    PromotedRsaAlg,
};
use super::super::{
    jwt_algorithm_allowed_by_profile, request_object_error_from_jose_header, ClientRegistry,
    RequestObjectValidationError,
};
use crate::util::decode_compact_jwt_header_without_duplicate_keys_with_max_len;

impl ClientRegistry {
    /// Verify a Request Object for the registered client using the configured verification key.
    ///
    /// # Errors
    ///
    /// Returns an error when the client is not registered, has no usable verification key, or the
    /// JOSE verification/claims validation fails.
    pub fn verify_request_object(
        &self,
        client_id: &str,
        request_jwt: &str,
        expected_audience: &str,
        crypto_profile: CryptoProfile,
    ) -> Result<RequestObjectVerification, RequestObjectValidationError> {
        let reg = self
            .try_get(client_id)
            .map_err(|err| {
                RequestObjectValidationError::Jose(RequestObjectError::Internal(err.to_string()))
            })?
            .ok_or_else(|| {
                RequestObjectValidationError::ClientNotRegistered(client_id.to_string())
            })?;

        let header = decode_compact_jwt_header_without_duplicate_keys_with_max_len(
            request_jwt,
            self.client_assertion_policy.jose_header_max_len,
        )
        .map_err(request_object_error_from_jose_header)
        .map_err(RequestObjectValidationError::Jose)?;
        let alg = header.alg;
        let promoted_rsa_alg = PromotedRsaAlg::from_jwt_algorithm(alg);
        if !jwt_algorithm_allowed_by_profile(alg, crypto_profile, promoted_rsa_alg.is_some()) {
            return Err(RequestObjectValidationError::Jose(
                RequestObjectError::UnsupportedAlgorithm(format!("{alg:?}")),
            ));
        }

        let expected_aud_list = if expected_audience.is_empty() {
            vec![]
        } else {
            vec![expected_audience.to_string()]
        };

        let leeway = self.client_assertion_policy.jwt_leeway_secs;

        let verification = if let Some(promoted_alg) = promoted_rsa_alg {
            let (modulus, exponent) = resolve_promoted_rsa_verification_key_with_state(
                &self.jwks_state,
                &self.jwks_policy,
                &reg,
                header.kid.as_deref(),
                promoted_alg,
            )
            .ok_or_else(|| {
                RequestObjectValidationError::VerificationKeyMissing(client_id.to_string())
            })?;
            match promoted_alg {
                PromotedRsaAlg::Rs256 => verify_request_object_rs256_promoted(
                    request_jwt,
                    &modulus,
                    &exponent,
                    &expected_aud_list,
                    leeway,
                ),
                PromotedRsaAlg::Ps256 => verify_request_object_ps256_promoted(
                    request_jwt,
                    &modulus,
                    &exponent,
                    &expected_aud_list,
                    leeway,
                ),
            }
        } else {
            let decoding_key = resolve_request_object_key_with_state(
                &self.jwks_state,
                &self.jwks_policy,
                &reg,
                header.kid.as_deref(),
                alg,
            )
            .ok_or_else(|| {
                RequestObjectValidationError::VerificationKeyMissing(client_id.to_string())
            })?;
            verify_request_object(request_jwt, &decoding_key, &expected_aud_list, leeway)
        }
        .map_err(RequestObjectValidationError::Jose)?;

        Ok(verification)
    }
}
