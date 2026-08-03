use aegaeon_jose::raw_json::{self, RawJsonBackend, RawJsonSurface};
use ffi::raw_json_structural::{
    self as ffi_raw_json_structural, RawJsonStructuralMember, RawJsonStructuralParseResult,
    RawJsonStructuralValueKind,
};
use serde_json::Value;
use std::collections::HashSet;

use super::types::{
    JwtAccessTokenAudience, JwtAccessTokenHeader, JwtAccessTokenParseError, JwtAccessTokenPayload,
};

pub(super) fn deserialize_jwt_access_token_header(
    payload: &[u8],
) -> Result<JwtAccessTokenHeader, JwtAccessTokenParseError> {
    let policy = raw_json::backend_policy_for_surface(RawJsonSurface::JwtAccessTokenHeader)
        .map_err(|_| {
            JwtAccessTokenParseError::backend_policy(RawJsonSurface::JwtAccessTokenHeader)
        })?;
    match policy.backend {
        RawJsonBackend::SerdeCompat => Err(JwtAccessTokenParseError::backend_policy(
            RawJsonSurface::JwtAccessTokenHeader,
        )),
        RawJsonBackend::VerifiedStructuralV1 => {
            deserialize_jwt_access_token_header_verified_structural(payload)
        }
    }
}

fn deserialize_jwt_access_token_header_verified_structural(
    payload: &[u8],
) -> Result<JwtAccessTokenHeader, JwtAccessTokenParseError> {
    let parse_result = ffi_raw_json_structural::parse_raw_json_structural(payload)
        .map_err(|_| JwtAccessTokenParseError::InvalidToken)?;
    decode_jwt_access_token_header_from_structural(payload, &parse_result)
        .map_err(|_| JwtAccessTokenParseError::InvalidToken)
}

fn decode_jwt_access_token_header_from_structural(
    payload: &[u8],
    parse_result: &RawJsonStructuralParseResult,
) -> Result<JwtAccessTokenHeader, ()> {
    let mut header = JwtAccessTokenHeader::default();
    let mut seen = HashSet::with_capacity(parse_result.members.len());

    for member in &parse_result.members {
        let key = decode_structural_key_bytes(&member.key)?;
        if !seen.insert(key.clone()) {
            return Err(());
        }

        match key.as_str() {
            "alg" => header.alg = parse_optional_header_string(payload, member)?,
            "typ" => header.typ = parse_optional_header_string(payload, member)?,
            "kid" => header.kid = parse_optional_header_string(payload, member)?,
            _ => {}
        }
    }

    Ok(header)
}

fn decode_structural_key_bytes(raw_key: &[u8]) -> Result<String, ()> {
    let mut quoted = Vec::with_capacity(raw_key.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(raw_key);
    quoted.push(b'"');

    serde_json::from_slice::<String>(&quoted).map_err(|_| ())
}

fn structural_value_slice<'a>(
    payload: &'a [u8],
    member: &RawJsonStructuralMember,
) -> Result<&'a [u8], ()> {
    member.value_slice(payload).ok_or(())
}

fn parse_optional_header_string(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Option<String>, ()> {
    match member.value_kind {
        RawJsonStructuralValueKind::Null => Ok(None),
        RawJsonStructuralValueKind::String => {
            serde_json::from_slice(structural_value_slice(payload, member)?)
                .map(Some)
                .map_err(|_| ())
        }
        RawJsonStructuralValueKind::Number
        | RawJsonStructuralValueKind::Bool
        | RawJsonStructuralValueKind::Object
        | RawJsonStructuralValueKind::Array => Ok(None),
    }
}

pub(super) fn deserialize_jwt_access_token_payload(
    payload: &[u8],
) -> Result<JwtAccessTokenPayload, JwtAccessTokenParseError> {
    let policy = raw_json::backend_policy_for_surface(RawJsonSurface::JwtAccessTokenPayload)
        .map_err(|_| {
            JwtAccessTokenParseError::backend_policy(RawJsonSurface::JwtAccessTokenPayload)
        })?;
    match policy.backend {
        RawJsonBackend::SerdeCompat => Err(JwtAccessTokenParseError::backend_policy(
            RawJsonSurface::JwtAccessTokenPayload,
        )),
        RawJsonBackend::VerifiedStructuralV1 => {
            deserialize_jwt_access_token_payload_verified_structural(payload)
        }
    }
}

fn deserialize_jwt_access_token_payload_verified_structural(
    payload: &[u8],
) -> Result<JwtAccessTokenPayload, JwtAccessTokenParseError> {
    let parse_result = ffi_raw_json_structural::parse_raw_json_structural(payload)
        .map_err(|_| JwtAccessTokenParseError::InvalidToken)?;
    decode_jwt_access_token_payload_from_structural(payload, &parse_result)
        .map_err(|_| JwtAccessTokenParseError::InvalidToken)
}

fn decode_jwt_access_token_payload_from_structural(
    payload: &[u8],
    parse_result: &RawJsonStructuralParseResult,
) -> Result<JwtAccessTokenPayload, ()> {
    let mut decoded = JwtAccessTokenPayload::default();
    let mut seen = HashSet::with_capacity(parse_result.members.len());

    for member in &parse_result.members {
        let key = decode_structural_key_bytes(&member.key)?;
        if !seen.insert(key.clone()) {
            return Err(());
        }

        match key.as_str() {
            "iss" => decoded.iss = parse_optional_header_string(payload, member)?,
            "sub" => decoded.sub = parse_optional_header_string(payload, member)?,
            "aud" => {
                decoded.aud_present = true;
                decoded.aud = parse_access_token_audience(payload, member)?;
            }
            "exp" => decoded.exp = parse_optional_u64_claim(payload, member)?,
            "iat" => decoded.iat = parse_optional_u64_claim(payload, member)?,
            "jti" => decoded.jti = parse_optional_header_string(payload, member)?,
            _ => {}
        }
    }

    Ok(decoded)
}

fn parse_optional_u64_claim(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Option<u64>, ()> {
    match member.value_kind {
        RawJsonStructuralValueKind::Number => {
            Ok(serde_json::from_slice(structural_value_slice(payload, member)?).ok())
        }
        RawJsonStructuralValueKind::Null
        | RawJsonStructuralValueKind::String
        | RawJsonStructuralValueKind::Bool
        | RawJsonStructuralValueKind::Object
        | RawJsonStructuralValueKind::Array => Ok(None),
    }
}

fn parse_access_token_audience(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Option<JwtAccessTokenAudience>, ()> {
    match member.value_kind {
        RawJsonStructuralValueKind::String => parse_optional_header_string(payload, member)
            .map(|value| value.map(JwtAccessTokenAudience::Single)),
        RawJsonStructuralValueKind::Array => {
            let values =
                serde_json::from_slice::<Vec<Value>>(structural_value_slice(payload, member)?)
                    .map_err(|_| ())?;
            let Some(audiences) = values
                .iter()
                .map(|value| value.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
            else {
                return Ok(None);
            };
            if audiences.is_empty() {
                return Ok(None);
            }
            Ok(Some(JwtAccessTokenAudience::Multiple(audiences)))
        }
        RawJsonStructuralValueKind::Null
        | RawJsonStructuralValueKind::Number
        | RawJsonStructuralValueKind::Bool
        | RawJsonStructuralValueKind::Object => Ok(None),
    }
}
