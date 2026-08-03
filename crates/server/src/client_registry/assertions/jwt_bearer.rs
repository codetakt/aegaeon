use aegaeon_jose::{
    algorithms::{Algorithm, CryptoProfile},
    jwt::{JwtClaims, ValidationContext},
    raw_json::RawJsonSurface,
};
use std::time::Duration;
use tracing::warn;

use super::super::request_object_keys::{
    resolve_promoted_rsa_verification_key_with_state, resolve_request_object_key_with_state,
    verify_jwt_bearer_rsa_promoted, JwtBearerPromotedRsaValidation, PromotedRsaAlg,
    PromotedRsaVerificationKey,
};
use super::super::{
    assertion_replay_ttl_secs, client_assertion_clock_error,
    client_assertion_error_from_jose_header, client_jwt_algorithm_name, metrics, record_jwt_replay,
    require_non_empty_jti, signed_assertion_error_result, unix_epoch_now_i64,
    ClientAssertionValidationError, ClientAssertionValidationResult, ClientRegistry,
    RegisteredClient, JWT_BEARER_REPLAY_NAMESPACE,
};
use crate::util::{
    decode_compact_jwt_header_without_duplicate_keys_with_max_len,
    verify_signed_assertion_registered_claims,
};

struct JwtBearerGrantAssertion<'a> {
    reg: &'a RegisteredClient,
    client_id: &'a str,
    assertion: &'a str,
    expected_token_aud: &'a str,
    expected_issuer_aud: &'a str,
    allow_client_subject: bool,
    crypto_profile: CryptoProfile,
    header: jsonwebtoken::Header,
}

struct JwtBearerAdmittedHeader {
    kid: Option<String>,
    alg: jsonwebtoken::Algorithm,
    promoted_rsa_alg: Option<PromotedRsaAlg>,
}

struct JwtBearerVerifiedClaims {
    claims: JwtClaims,
    now: i64,
    leeway: u64,
}

impl ClientRegistry {
    pub fn try_validate_jwt_bearer_grant_assertion(
        &self,
        client_id: &str,
        assertion: &str,
        expected_token_aud: &str,
        expected_issuer_aud: &str,
        allow_client_subject: bool,
        crypto_profile: CryptoProfile,
    ) -> ClientAssertionValidationResult {
        let Some(reg) = self
            .try_get(client_id)
            .map_err(|err| ClientAssertionValidationError::Internal(err.to_string()))?
        else {
            return Ok(None);
        };
        let header = decode_compact_jwt_header_without_duplicate_keys_with_max_len(
            assertion,
            self.client_assertion_policy.jose_header_max_len,
        )
        .map_err(client_assertion_error_from_jose_header)?;
        self.validate_jwt_bearer_grant_assertion_with_admitted_header(&JwtBearerGrantAssertion {
            reg: &reg,
            client_id,
            assertion,
            expected_token_aud,
            expected_issuer_aud,
            allow_client_subject,
            crypto_profile,
            header,
        })
    }

    fn validate_jwt_bearer_grant_assertion_with_admitted_header(
        &self,
        input: &JwtBearerGrantAssertion<'_>,
    ) -> ClientAssertionValidationResult {
        let Some(header) = self.admit_jwt_bearer_header(input) else {
            return Ok(None);
        };
        let Some(verified) = self.verify_jwt_bearer_claims(input, &header)? else {
            return Ok(None);
        };
        let Some(subject) = validate_jwt_bearer_subject_policy(input, &verified.claims) else {
            return Ok(None);
        };
        if !self.record_jwt_bearer_replay(input, &verified)? {
            return Ok(None);
        }

        Ok(Some(subject))
    }

    fn admit_jwt_bearer_header(
        &self,
        input: &JwtBearerGrantAssertion<'_>,
    ) -> Option<JwtBearerAdmittedHeader> {
        let kid = input.header.kid.clone();
        let alg = input.header.alg;

        let allowed = &self.client_assertion_policy.allowed_algorithms;
        let Some(alg_str) = client_jwt_algorithm_name(alg) else {
            metrics::record_runtime_bcp_noncompliant("jwt_bearer_alg_not_allowed");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                alg = ?alg,
                "jwt bearer assertion alg not supported by runtime"
            );
            return None;
        };
        if !allowed.contains(alg_str) {
            metrics::record_runtime_bcp_noncompliant("jwt_bearer_alg_not_allowed");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                alg = %alg_str,
                "jwt bearer assertion alg not allowed"
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
            metrics::record_runtime_bcp_noncompliant("jwt_bearer_kid_missing");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                "jwt bearer assertion kid missing while required"
            );
            return None;
        }

        Some(JwtBearerAdmittedHeader {
            kid,
            alg,
            promoted_rsa_alg,
        })
    }

    fn verify_jwt_bearer_claims(
        &self,
        input: &JwtBearerGrantAssertion<'_>,
        header: &JwtBearerAdmittedHeader,
    ) -> Result<Option<JwtBearerVerifiedClaims>, ClientAssertionValidationError> {
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
            match verify_jwt_bearer_rsa_promoted(
                input.assertion,
                PromotedRsaVerificationKey {
                    modulus: &modulus,
                    exponent: &exponent,
                },
                promoted_alg,
                JwtBearerPromotedRsaValidation {
                    client_id: input.client_id,
                    expected_token_aud: input.expected_token_aud,
                    expected_issuer_aud: input.expected_issuer_aud,
                    allow_client_subject: input.allow_client_subject,
                    leeway,
                },
            ) {
                Ok(claims) => claims,
                Err(err) => {
                    return signed_assertion_error_result(err, "jwt-bearer-assertion-payload")
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

            let mut val = jsonwebtoken::Validation::new(header.alg);
            val.validate_exp = true;
            val.validate_nbf = true;
            if input.allow_client_subject {
                val.set_audience(&[input.expected_token_aud, input.expected_issuer_aud]);
            } else {
                val.set_audience(&[input.expected_token_aud]);
            }
            val.leeway = leeway;

            match verify_signed_assertion_registered_claims(
                input.assertion,
                &dkey,
                &val,
                RawJsonSurface::JwtBearerAssertionPayload,
            ) {
                Ok(claims) => claims,
                Err(err) => {
                    return signed_assertion_error_result(err, "jwt-bearer-assertion-payload")
                        .map(|_| None);
                }
            }
        };

        let Some(now) = unix_epoch_now_i64("jwt bearer assertion validation clock") else {
            return Err(client_assertion_clock_error(
                "jwt bearer assertion validation clock",
            ));
        };
        let allowed_audiences = jwt_bearer_allowed_audiences(input);
        let ctx = ValidationContext::builder()
            .now(now)
            .leeway(Duration::from_secs(leeway))
            .expected_issuer(input.client_id.to_string())
            .allowed_audiences(allowed_audiences)
            .require_issuer(true)
            .require_subject(true)
            .require_audience(true)
            .require_exp(true)
            .build();
        if let Err(err) = claims.validate(&ctx) {
            metrics::record_runtime_bcp_noncompliant("jwt_bearer_claim_validation");
            warn!(
                target: "jwks",
                client_id = %input.client_id,
                error = %err,
                "jwt bearer assertion claim validation failed"
            );
            return Ok(None);
        }

        Ok(Some(JwtBearerVerifiedClaims {
            claims,
            now,
            leeway,
        }))
    }

    fn record_jwt_bearer_replay(
        &self,
        input: &JwtBearerGrantAssertion<'_>,
        verified: &JwtBearerVerifiedClaims,
    ) -> Result<bool, ClientAssertionValidationError> {
        let Some(jti) =
            require_non_empty_jti(&verified.claims, "jwt_bearer_jti_missing", input.client_id)
        else {
            return Ok(false);
        };
        let window = self.client_assertion_policy.jwt_bearer_replay_window_secs;
        let Some(replay_ttl) = assertion_replay_ttl_secs(
            &verified.claims,
            verified.now,
            verified.leeway,
            window,
            "jwt_bearer_jti_window_exceeded",
            "jwt_bearer_temporal_overflow",
            input.client_id,
        ) else {
            return Ok(false);
        };
        match record_jwt_replay(
            &self.jwt_replay_store,
            JWT_BEARER_REPLAY_NAMESPACE,
            input.client_id,
            jti,
            replay_ttl,
        ) {
            Ok(()) => Ok(true),
            Err(crate::middleware::ReplayStoreError::Replay) => Ok(false),
            Err(error) => Err(ClientAssertionValidationError::Internal(format!(
                "jwt_bearer replay store failed: {error}"
            ))),
        }
    }
}

fn jwt_bearer_allowed_audiences(input: &JwtBearerGrantAssertion<'_>) -> Vec<String> {
    let mut allowed_audiences = vec![input.expected_token_aud.to_string()];
    if input.allow_client_subject {
        allowed_audiences.push(input.expected_issuer_aud.to_string());
    }
    allowed_audiences
}

fn jwt_claims_audience_contains(claims: &JwtClaims, expected: &str) -> bool {
    match claims.aud.as_ref() {
        Some(serde_json::Value::String(s)) => s == expected,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| match v {
            serde_json::Value::String(s) => s == expected,
            _ => false,
        }),
        _ => false,
    }
}

fn validate_jwt_bearer_subject_policy(
    input: &JwtBearerGrantAssertion<'_>,
    claims: &JwtClaims,
) -> Option<String> {
    let subject = claims
        .sub
        .as_deref()
        .map(str::trim)
        .filter(|subject| !subject.is_empty())?;
    let aud_matches_token_endpoint = jwt_claims_audience_contains(claims, input.expected_token_aud);
    let aud_matches_issuer = jwt_claims_audience_contains(claims, input.expected_issuer_aud);

    if subject == input.client_id {
        return validate_jwt_bearer_client_subject_policy(
            input,
            aud_matches_issuer,
            aud_matches_token_endpoint,
        )
        .then(|| subject.to_string());
    }
    if !aud_matches_token_endpoint {
        metrics::record_runtime_bcp_noncompliant("jwt_bearer_audience_mismatch");
        warn!(
            target: "jwks",
            client_id = %input.client_id,
            expected_token_aud = %input.expected_token_aud,
            "jwt bearer assertion audience mismatch"
        );
        return None;
    }

    Some(subject.to_string())
}

fn validate_jwt_bearer_client_subject_policy(
    input: &JwtBearerGrantAssertion<'_>,
    aud_matches_issuer: bool,
    aud_matches_token_endpoint: bool,
) -> bool {
    if !input.allow_client_subject {
        metrics::record_runtime_bcp_noncompliant("jwt_bearer_subject_equals_client_id");
        warn!(
            target: "jwks",
            client_id = %input.client_id,
            "jwt bearer assertion subject matches client_id (rejecting to prevent jwt kind confusion)"
        );
        return false;
    }
    if !aud_matches_issuer || aud_matches_token_endpoint {
        metrics::record_runtime_bcp_noncompliant("jwt_bearer_client_subject_audience_mismatch");
        warn!(
            target: "jwks",
            client_id = %input.client_id,
            expected_issuer_aud = %input.expected_issuer_aud,
            expected_token_aud = %input.expected_token_aud,
            "jwt bearer assertion with client subject must target issuer audience only"
        );
        return false;
    }
    true
}
