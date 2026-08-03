use super::RequiredRs256Error;
use crate::oidc::id_token::{Audience, IdTokenClaims};
use aegaeon_jose::raw_json::{self, RawJsonBackend, RawJsonSurface};
use ffi::raw_json_structural::{
    self as ffi_raw_json_structural, RawJsonStructuralMember, RawJsonStructuralParseError,
    RawJsonStructuralParseResult, RawJsonStructuralValueKind,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Decode an OIDC ID Token payload after raw JSON admission for the
/// `oidc-id-token-payload` surface.
///
/// # Errors
///
/// Returns [`RequiredRs256Error`] when raw JSON admission or typed claim decoding fails.
pub(crate) fn decode_id_token_payload_claims_without_duplicate_keys(
    payload: &[u8],
) -> Result<IdTokenClaims, RequiredRs256Error> {
    let policy = raw_json::backend_policy_for_surface(RawJsonSurface::OidcIdTokenPayload)
        .map_err(|err| RequiredRs256Error::Internal(err.to_string()))?;

    match policy.backend {
        RawJsonBackend::SerdeCompat => Err(RequiredRs256Error::Internal(
            "serde-compat backend is not available for OIDC ID Token payloads".to_string(),
        )),
        RawJsonBackend::VerifiedStructuralV1 => {
            decode_payload_without_duplicate_keys_verified_structural(payload)
        }
    }
}

fn decode_payload_without_duplicate_keys_verified_structural(
    payload: &[u8],
) -> Result<IdTokenClaims, RequiredRs256Error> {
    let parse_result =
        ffi_raw_json_structural::parse_raw_json_structural(payload).map_err(|err| match err {
            RawJsonStructuralParseError::ParserUnavailable
            | RawJsonStructuralParseError::Internal => {
                RequiredRs256Error::Internal(err.to_string())
            }
            RawJsonStructuralParseError::BufferTooLarge
            | RawJsonStructuralParseError::InvalidJson
            | RawJsonStructuralParseError::InvalidShape
            | RawJsonStructuralParseError::TrailingBytes => RequiredRs256Error::InvalidPayload,
        })?;

    decode_id_token_claims_from_structural(payload, &parse_result)
}

fn decode_id_token_claims_from_structural(
    payload: &[u8],
    parse_result: &RawJsonStructuralParseResult,
) -> Result<IdTokenClaims, RequiredRs256Error> {
    let mut claims = StructuralClaims::with_capacity(parse_result.members.len());

    for member in &parse_result.members {
        let key = decode_structural_key_bytes(&member.key)?;
        if !claims.seen.insert(key.clone()) {
            return Err(RequiredRs256Error::InvalidPayload);
        }

        claims.set(payload, member, key)?;
    }

    claims.finish()
}

struct StructuralClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    exp: Option<i64>,
    iat: Option<i64>,
    auth_time: Option<i64>,
    nonce: Option<String>,
    acr: Option<String>,
    amr: Option<Vec<String>>,
    azp: Option<String>,
    sid: Option<String>,
    at_hash: Option<String>,
    c_hash: Option<String>,
    nbf: Option<i64>,
    jti: Option<String>,
    additional_claims: HashMap<String, Value>,
    seen: HashSet<String>,
}

impl StructuralClaims {
    fn with_capacity(member_count: usize) -> Self {
        Self {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            iat: None,
            auth_time: None,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            sid: None,
            at_hash: None,
            c_hash: None,
            nbf: None,
            jti: None,
            additional_claims: HashMap::new(),
            seen: HashSet::with_capacity(member_count),
        }
    }

    fn set(
        &mut self,
        payload: &[u8],
        member: &RawJsonStructuralMember,
        key: String,
    ) -> Result<(), RequiredRs256Error> {
        match key.as_str() {
            "iss" => self.iss = Some(parse_required_string_claim(payload, member)?),
            "sub" => self.sub = Some(parse_required_string_claim(payload, member)?),
            "aud" => self.aud = Some(parse_audience_claim(payload, member)?),
            "exp" => self.exp = Some(parse_required_i64_claim(payload, member)?),
            "iat" => self.iat = Some(parse_required_i64_claim(payload, member)?),
            "auth_time" => self.auth_time = parse_optional_i64_claim(payload, member)?,
            "nonce" => self.nonce = parse_optional_string_claim(payload, member)?,
            "acr" => self.acr = parse_optional_string_claim(payload, member)?,
            "amr" => self.amr = parse_optional_string_vec_claim(payload, member)?,
            "azp" => self.azp = parse_optional_string_claim(payload, member)?,
            "sid" => self.sid = parse_optional_string_claim(payload, member)?,
            "at_hash" => self.at_hash = parse_optional_string_claim(payload, member)?,
            "c_hash" => self.c_hash = parse_optional_string_claim(payload, member)?,
            "nbf" => self.nbf = parse_optional_i64_claim(payload, member)?,
            "jti" => self.jti = parse_optional_string_claim(payload, member)?,
            _ => {
                self.additional_claims
                    .insert(key, parse_additional_claim_value(payload, member)?);
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<IdTokenClaims, RequiredRs256Error> {
        Ok(IdTokenClaims {
            iss: self.iss.ok_or(RequiredRs256Error::InvalidPayload)?,
            sub: self.sub.ok_or(RequiredRs256Error::InvalidPayload)?,
            aud: self.aud.ok_or(RequiredRs256Error::InvalidPayload)?,
            exp: self.exp.ok_or(RequiredRs256Error::InvalidPayload)?,
            iat: self.iat.ok_or(RequiredRs256Error::InvalidPayload)?,
            auth_time: self.auth_time,
            nonce: self.nonce,
            acr: self.acr,
            amr: self.amr,
            azp: self.azp,
            sid: self.sid,
            at_hash: self.at_hash,
            c_hash: self.c_hash,
            nbf: self.nbf,
            jti: self.jti,
            additional_claims: self.additional_claims,
        })
    }
}

fn decode_structural_key_bytes(raw_key: &[u8]) -> Result<String, RequiredRs256Error> {
    let mut quoted = Vec::with_capacity(raw_key.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(raw_key);
    quoted.push(b'"');

    serde_json::from_slice::<String>(&quoted).map_err(|_| RequiredRs256Error::InvalidPayload)
}

fn value_slice<'a>(
    payload: &'a [u8],
    member: &RawJsonStructuralMember,
) -> Result<&'a [u8], RequiredRs256Error> {
    member.value_slice(payload).ok_or_else(|| {
        RequiredRs256Error::Internal(
            "OIDC ID Token payload structural span out of bounds".to_string(),
        )
    })
}

fn parse_required_string_claim(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<String, RequiredRs256Error> {
    if member.value_kind != RawJsonStructuralValueKind::String {
        return Err(RequiredRs256Error::InvalidPayload);
    }
    serde_json::from_slice(value_slice(payload, member)?)
        .map_err(|_| RequiredRs256Error::InvalidPayload)
}

fn parse_optional_string_claim(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Option<String>, RequiredRs256Error> {
    match member.value_kind {
        RawJsonStructuralValueKind::Null => Ok(None),
        RawJsonStructuralValueKind::String => serde_json::from_slice(value_slice(payload, member)?)
            .map(Some)
            .map_err(|_| RequiredRs256Error::InvalidPayload),
        _ => Err(RequiredRs256Error::InvalidPayload),
    }
}

fn parse_required_i64_claim(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<i64, RequiredRs256Error> {
    if member.value_kind != RawJsonStructuralValueKind::Number {
        return Err(RequiredRs256Error::InvalidPayload);
    }
    serde_json::from_slice(value_slice(payload, member)?)
        .map_err(|_| RequiredRs256Error::InvalidPayload)
}

fn parse_optional_i64_claim(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Option<i64>, RequiredRs256Error> {
    match member.value_kind {
        RawJsonStructuralValueKind::Null => Ok(None),
        RawJsonStructuralValueKind::Number => serde_json::from_slice(value_slice(payload, member)?)
            .map(Some)
            .map_err(|_| RequiredRs256Error::InvalidPayload),
        _ => Err(RequiredRs256Error::InvalidPayload),
    }
}

fn parse_optional_string_vec_claim(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Option<Vec<String>>, RequiredRs256Error> {
    match member.value_kind {
        RawJsonStructuralValueKind::Null => Ok(None),
        RawJsonStructuralValueKind::Array => serde_json::from_slice(value_slice(payload, member)?)
            .map(Some)
            .map_err(|_| RequiredRs256Error::InvalidPayload),
        _ => Err(RequiredRs256Error::InvalidPayload),
    }
}

fn parse_audience_claim(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Audience, RequiredRs256Error> {
    match member.value_kind {
        RawJsonStructuralValueKind::String => {
            parse_required_string_claim(payload, member).map(Audience::Single)
        }
        RawJsonStructuralValueKind::Array => serde_json::from_slice(value_slice(payload, member)?)
            .map(Audience::Multiple)
            .map_err(|_| RequiredRs256Error::InvalidPayload),
        _ => Err(RequiredRs256Error::InvalidPayload),
    }
}

fn parse_additional_claim_value(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Value, RequiredRs256Error> {
    serde_json::from_slice(value_slice(payload, member)?)
        .map_err(|_| RequiredRs256Error::InvalidPayload)
}
