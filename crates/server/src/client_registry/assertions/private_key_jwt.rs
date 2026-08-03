use aegaeon_jose::{
    algorithms::{Algorithm, CryptoProfile},
    jwt::{JwtClaims, ValidationContext},
    raw_json::RawJsonSurface,
};
use std::time::Duration;
use tracing::warn;

use super::super::request_object_keys::{
    resolve_promoted_rsa_verification_key_with_state, resolve_request_object_key_with_state,
    verify_private_key_jwt_rsa_promoted, PromotedRsaAlg,
};
use super::super::{
    assertion_replay_ttl_secs, client_assertion_clock_error,
    client_assertion_error_from_jose_header, client_jwt_algorithm_name, metrics, record_jwt_replay,
    require_non_empty_jti, signed_assertion_error_result, unix_epoch_now_i64,
    ClientAssertionValidationError, ClientAssertionValidationResult, ClientRegistry,
    RegisteredClient, PRIVATE_KEY_JWT_REPLAY_NAMESPACE,
};
use crate::util::{
    decode_compact_jwt_header_without_duplicate_keys_with_max_len,
    verify_signed_assertion_registered_claims,
};

struct PrivateKeyJwtAssertion<'a> {
    reg: &'a RegisteredClient,
    client_id: &'a str,
    assertion: &'a str,
    expected_aud: &'a str,
    crypto_profile: CryptoProfile,
    header: jsonwebtoken::Header,
}

struct PrivateKeyJwtAdmittedHeader {
    kid: Option<String>,
    alg: jsonwebtoken::Algorithm,
    promoted_rsa_alg: Option<PromotedRsaAlg>,
}

struct PrivateKeyJwtVerifiedClaims {
    claims: JwtClaims,
    now: i64,
    leeway: u64,
}

impl ClientRegistry {
    pub fn try_validate_private_key_jwt(
        &self,
        client_id: &str,
        assertion: &str,
        expected_aud: &str,
        crypto_profile: CryptoProfile,
    ) -> ClientAssertionValidationResult {
        let Some(reg) = self
            .try_get(client_id)
            .map_err(|err| ClientAssertionValidationError::Internal(err.to_string()))?
        else {
            return Ok(None);
        };
        if !Self::registered_auth_method_matches(&reg, "private_key_jwt") {
            warn!(
                target: "jwks",
                client_id = %client_id,
                registered_auth_method = %reg.token_endpoint_auth_method,
                "client jwt auth method mismatch"
            );
            return Ok(None);
        }
        let header = decode_compact_jwt_header_without_duplicate_keys_with_max_len(
            assertion,
            self.client_assertion_policy.jose_header_max_len,
        )
        .map_err(client_assertion_error_from_jose_header)?;
        self.validate_private_key_jwt_with_admitted_header(&PrivateKeyJwtAssertion {
            reg: &reg,
            client_id,
            assertion,
            expected_aud,
            crypto_profile,
            header,
        })
    }

    fn validate_private_key_jwt_with_admitted_header(
        &self,
        input: &PrivateKeyJwtAssertion<'_>,
    ) -> ClientAssertionValidationResult {
        let Some(header) = self.admit_private_key_jwt_header(input) else {
            return Ok(None);
        };
        let Some(verified) = self.verify_private_key_jwt_claims(input, &header)? else {
            return Ok(None);
        };
        if !private_key_jwt_subject_policy_matches(input, &verified.claims) {
            return Ok(None);
        }
        if !self.record_private_key_jwt_replay(input, &verified)? {
            return Ok(None);
        }

        Ok(Some(input.client_id.to_string()))
    }

    fn admit_private_key_jwt_header(
        &self,
        input: &PrivateKeyJwtAssertion<'_>,
    ) -> Option<PrivateKeyJwtAdmittedHeader> {
        let kid = input.header.kid.clone();
        let alg = input.header.alg;
        let allowed = &self.client_assertion_policy.allowed_algorithms;
        let Some(alg_str) = client_jwt_algorithm_name(alg) else {
            metrics::record_runtime_bcp_noncompliant("alg_not_allowed");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                alg = ?alg,
                "client jwt alg not supported by runtime"
            );
            return None;
        };
        if !allowed.contains(alg_str) {
            metrics::record_runtime_bcp_noncompliant("alg_not_allowed");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                alg = %alg_str,
                "client jwt alg not allowed"
            );
            return None;
        }
        if input
            .reg
            .token_endpoint_auth_signing_alg
            .as_deref()
            .is_some_and(|registered_alg| registered_alg != alg_str)
        {
            metrics::record_runtime_bcp_noncompliant("alg_not_registered");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                alg = %alg_str,
                registered_alg = ?input.reg.token_endpoint_auth_signing_alg,
                "client jwt alg does not match registered token_endpoint_auth_signing_alg"
            );
            return None;
        }
        let promoted_rsa_alg = PromotedRsaAlg::from_jwt_algorithm(alg);

        if let Ok(aegaeon_alg) = Algorithm::from_string(alg_str) {
            // Non-promoted assertions verify via the compat `jsonwebtoken` backend.
            if promoted_rsa_alg.is_none()
                && !input.crypto_profile.allows_on_compat_dispatch(&aegaeon_alg)
            {
                warn!(target: "jwks", client_id=%input.client_id, alg=%alg_str,
                      "algorithm rejected by crypto profile");
                return None;
            }
        }
        if self.client_assertion_policy.require_kid && kid.is_none() {
            metrics::record_runtime_bcp_noncompliant("kid_missing");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                "client jwt kid missing while required"
            );
            return None;
        }

        Some(PrivateKeyJwtAdmittedHeader {
            kid,
            alg,
            promoted_rsa_alg,
        })
    }

    fn verify_private_key_jwt_claims(
        &self,
        input: &PrivateKeyJwtAssertion<'_>,
        header: &PrivateKeyJwtAdmittedHeader,
    ) -> Result<Option<PrivateKeyJwtVerifiedClaims>, ClientAssertionValidationError> {
        let leeway = self.client_assertion_policy.jwt_leeway_secs;
        let claims = if let Some(promoted_alg) = header.promoted_rsa_alg {
            let Some((modulus, exponent)) = resolve_promoted_rsa_verification_key_with_state(
                &self.jwks_state,
                &self.jwks_policy,
                input.reg,
                header.kid.as_deref(),
                promoted_alg,
            ) else {
                return Ok(None);
            };
            match verify_private_key_jwt_rsa_promoted(
                input.assertion,
                &modulus,
                &exponent,
                promoted_alg,
                input.client_id,
                input.expected_aud,
                leeway,
            ) {
                Ok(claims) => claims,
                Err(err) => {
                    return signed_assertion_error_result(err, "private-key-jwt-payload")
                        .map(|_| None);
                }
            }
        } else {
            let Some(dkey) = resolve_request_object_key_with_state(
                &self.jwks_state,
                &self.jwks_policy,
                input.reg,
                header.kid.as_deref(),
                header.alg,
            ) else {
                return Ok(None);
            };

            let val =
                private_key_jwt_jsonwebtoken_validation(header.alg, input.expected_aud, leeway);
            match verify_signed_assertion_registered_claims(
                input.assertion,
                &dkey,
                &val,
                RawJsonSurface::PrivateKeyJwtPayload,
            ) {
                Ok(claims) => claims,
                Err(err) => {
                    return signed_assertion_error_result(err, "private-key-jwt-payload")
                        .map(|_| None);
                }
            }
        };

        let Some(now) = unix_epoch_now_i64("private-key-jwt validation clock") else {
            return Err(client_assertion_clock_error(
                "private-key-jwt validation clock",
            ));
        };
        let ctx = ValidationContext::builder()
            .now(now)
            .leeway(Duration::from_secs(leeway))
            .expected_issuer(input.client_id.to_string())
            .expected_subject(input.client_id.to_string())
            .allowed_audiences([input.expected_aud.to_string()])
            .require_issuer(true)
            .require_subject(true)
            .require_audience(true)
            .require_exp(true)
            .build();
        if let Err(err) = claims.validate(&ctx) {
            metrics::record_runtime_bcp_noncompliant("claim_validation");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                error = %err,
                "client jwt claim validation failed"
            );
            return Ok(None);
        }

        Ok(Some(PrivateKeyJwtVerifiedClaims {
            claims,
            now,
            leeway,
        }))
    }

    fn record_private_key_jwt_replay(
        &self,
        input: &PrivateKeyJwtAssertion<'_>,
        verified: &PrivateKeyJwtVerifiedClaims,
    ) -> Result<bool, ClientAssertionValidationError> {
        let Some(jti) = require_non_empty_jti(&verified.claims, "jti_missing", input.client_id)
        else {
            return Ok(false);
        };
        let window = self
            .client_assertion_policy
            .private_key_jwt_replay_window_secs;
        let Some(replay_ttl) = assertion_replay_ttl_secs(
            &verified.claims,
            verified.now,
            verified.leeway,
            window,
            "jti_window_exceeded",
            "jti_temporal_overflow",
            input.client_id,
        ) else {
            return Ok(false);
        };
        match record_jwt_replay(
            &self.jwt_replay_store,
            PRIVATE_KEY_JWT_REPLAY_NAMESPACE,
            input.client_id,
            jti,
            replay_ttl,
        ) {
            Ok(()) => Ok(true),
            Err(crate::middleware::ReplayStoreError::Replay) => Ok(false),
            Err(error) => Err(ClientAssertionValidationError::Internal(format!(
                "private_key_jwt replay store failed: {error}"
            ))),
        }
    }
}

fn private_key_jwt_jsonwebtoken_validation(
    alg: jsonwebtoken::Algorithm,
    expected_aud: &str,
    leeway: u64,
) -> jsonwebtoken::Validation {
    let mut val = jsonwebtoken::Validation::new(alg);
    val.validate_exp = true;
    val.validate_nbf = true;
    val.set_audience(&[expected_aud]);
    val.leeway = leeway;
    val
}

fn private_key_jwt_subject_policy_matches(
    input: &PrivateKeyJwtAssertion<'_>,
    claims: &JwtClaims,
) -> bool {
    claims.sub.as_deref() == Some(input.client_id) && claims.iss.as_deref() == Some(input.client_id)
}
