use aegaeon_jose::jwk::JwkSet;
use aegaeon_jose::jws::{self, Jws};
use aegaeon_jose::policy::JoseContext;

use super::{
    decode_jwk_material, raw_payload, validate_entity_url, verification_key_for_alg,
    FederationError, TrustMark, TrustMarkClaims, DEFAULT_CLOCK_SKEW_SECS,
};

/// Verify a Trust Mark JWS and validate its claims.
///
/// # Errors
///
/// Returns [`FederationError`] when signature verification fails, the payload is malformed, or
/// trust mark claims violate subject, identifier, or temporal requirements.
pub fn verify_trust_mark(
    trust_mark: &TrustMark,
    expected_subject: &str,
    issuer_jwks: &JwkSet,
    now: i64,
) -> Result<TrustMarkClaims, FederationError> {
    let parsed = Jws::from_compact(&trust_mark.trust_mark)?;
    let alg = &parsed.header.alg;
    let ctx = JoseContext::default();

    let mut last_err = None;
    let mut verified_payload = None;

    for key in issuer_jwks.signature_keys() {
        if let Some(ref header_kid) = parsed.header.kid {
            if key.kid.as_deref() != Some(header_kid.as_str()) {
                continue;
            }
        }

        let decoded = match decode_jwk_material(key) {
            Ok(decoded) => decoded,
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };
        let verification_key = match verification_key_for_alg(key, &decoded, alg) {
            Ok(key) => key,
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };

        match jws::verify_compact_with_context(&trust_mark.trust_mark, verification_key, &ctx) {
            Ok(payload_bytes) => {
                verified_payload = Some(payload_bytes);
                break;
            }
            Err(err) => {
                last_err = Some(FederationError::Jws(err));
            }
        }
    }

    let payload_bytes =
        verified_payload.ok_or_else(|| last_err.unwrap_or(FederationError::NoSuitableKey))?;
    let claims = raw_payload::parse_trust_mark_claims_payload(&payload_bytes)?;
    validate_trust_mark_claims(&claims, expected_subject, &trust_mark.id, now)?;
    Ok(claims)
}

pub(in crate::federation) fn validate_trust_mark_claims(
    claims: &TrustMarkClaims,
    expected_subject: &str,
    expected_id: &str,
    now: i64,
) -> Result<(), FederationError> {
    if validate_entity_url(&claims.iss).is_err() {
        return Err(FederationError::TrustMark(
            "iss must be an HTTPS entity URL".into(),
        ));
    }
    if claims.sub != expected_subject {
        return Err(FederationError::TrustMark(format!(
            "sub '{}' does not match expected entity '{}'",
            claims.sub, expected_subject,
        )));
    }
    if claims.id != expected_id {
        return Err(FederationError::TrustMark(format!(
            "id '{}' does not match envelope id '{}'",
            claims.id, expected_id,
        )));
    }

    let now_with_skew = now.checked_add(DEFAULT_CLOCK_SKEW_SECS).ok_or_else(|| {
        FederationError::TrustMark(
            "trust mark now plus clock skew is outside representable time".into(),
        )
    })?;
    if claims.iat > now_with_skew {
        return Err(FederationError::TrustMark(
            "trust mark issued in the future".into(),
        ));
    }

    if let Some(exp) = claims.exp {
        let exp_with_skew = exp.checked_add(DEFAULT_CLOCK_SKEW_SECS).ok_or_else(|| {
            FederationError::TrustMark(
                "trust mark exp plus clock skew is outside representable time".into(),
            )
        })?;
        if now > exp_with_skew {
            return Err(FederationError::TrustMark("trust mark has expired".into()));
        }
        if exp <= claims.iat {
            return Err(FederationError::TrustMark(
                "exp must be greater than iat".into(),
            ));
        }
    }

    Ok(())
}
