use crate::federation::{EntityStatement, FederationError, TrustMarkClaims};
use crate::util::{validate_json_without_duplicate_object_keys, JsonAdmissionError};
use ffi::raw_json_structural::{
    self as ffi_raw_json_structural, RawJsonStructuralMember, RawJsonStructuralParseError,
    RawJsonStructuralParseResult, RawJsonStructuralValueKind,
};
use serde::de::DeserializeOwned;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FederationStructuralDecodeError {
    DuplicateKey,
    InvalidPayload,
    Internal(&'static str),
}

pub(super) fn parse_entity_statement_payload_verified_structural(
    payload: &[u8],
) -> Result<EntityStatement, FederationError> {
    let parse_result = match ffi_raw_json_structural::parse_raw_json_structural(payload) {
        Ok(parse_result) => parse_result,
        Err(err) => return Err(map_entity_statement_structural_parse_error(payload, err)),
    };
    decode_entity_statement_from_structural(payload, &parse_result)
        .map_err(|err| map_entity_statement_structural_decode_error(payload, err))
}

pub(super) fn parse_trust_mark_claims_payload_verified_structural(
    payload: &[u8],
) -> Result<TrustMarkClaims, FederationError> {
    let parse_result = match ffi_raw_json_structural::parse_raw_json_structural(payload) {
        Ok(parse_result) => parse_result,
        Err(err) => return Err(map_trust_mark_structural_parse_error(payload, err)),
    };
    decode_trust_mark_claims_from_structural(payload, &parse_result)
        .map_err(|err| map_trust_mark_structural_decode_error(payload, err))
}

fn decode_entity_statement_from_structural(
    payload: &[u8],
    parse_result: &RawJsonStructuralParseResult,
) -> Result<EntityStatement, FederationStructuralDecodeError> {
    let mut iss = None;
    let mut sub = None;
    let mut iat = None;
    let mut exp = None;
    let mut jwks = None;
    let mut metadata = None;
    let mut metadata_policy = None;
    let mut constraints = None;
    let mut trust_marks = None;
    let mut authority_hints = None;
    let mut source_endpoint = None;
    let mut seen = HashSet::with_capacity(parse_result.members.len());

    for member in &parse_result.members {
        let key = decode_structural_key_bytes(&member.key)?;
        if !seen.insert(key.clone()) {
            return Err(FederationStructuralDecodeError::DuplicateKey);
        }

        match key.as_str() {
            "iss" => iss = Some(parse_required_structural_string(payload, member)?),
            "sub" => sub = Some(parse_required_structural_string(payload, member)?),
            "iat" => iat = Some(parse_required_structural_i64(payload, member)?),
            "exp" => exp = Some(parse_required_structural_i64(payload, member)?),
            "jwks" => jwks = parse_optional_structural_value(payload, member)?,
            "metadata" => metadata = parse_optional_structural_value(payload, member)?,
            "metadata_policy" => {
                metadata_policy = parse_optional_structural_value(payload, member)?
            }
            "constraints" => constraints = parse_optional_structural_value(payload, member)?,
            "trust_marks" => trust_marks = parse_optional_structural_value(payload, member)?,
            "authority_hints" => {
                authority_hints = parse_optional_structural_value(payload, member)?
            }
            "source_endpoint" => {
                source_endpoint = parse_optional_structural_string(payload, member)?
            }
            _ => {}
        }
    }

    Ok(EntityStatement {
        iss: iss.ok_or(FederationStructuralDecodeError::InvalidPayload)?,
        sub: sub.ok_or(FederationStructuralDecodeError::InvalidPayload)?,
        iat: iat.ok_or(FederationStructuralDecodeError::InvalidPayload)?,
        exp: exp.ok_or(FederationStructuralDecodeError::InvalidPayload)?,
        jwks,
        metadata,
        metadata_policy,
        constraints,
        trust_marks,
        authority_hints,
        source_endpoint,
    })
}

fn decode_trust_mark_claims_from_structural(
    payload: &[u8],
    parse_result: &RawJsonStructuralParseResult,
) -> Result<TrustMarkClaims, FederationStructuralDecodeError> {
    let mut iss = None;
    let mut sub = None;
    let mut id = None;
    let mut iat = None;
    let mut exp = None;
    let mut ref_: Option<Option<String>> = None;
    let mut seen = HashSet::with_capacity(parse_result.members.len());

    for member in &parse_result.members {
        let key = decode_structural_key_bytes(&member.key)?;
        if !seen.insert(key.clone()) {
            return Err(FederationStructuralDecodeError::DuplicateKey);
        }

        match key.as_str() {
            "iss" => iss = Some(parse_required_structural_string(payload, member)?),
            "sub" => sub = Some(parse_required_structural_string(payload, member)?),
            "trust_mark_type" | "id" => {
                set_structural_once(&mut id, parse_required_structural_string(payload, member)?)?
            }
            "iat" => iat = Some(parse_required_structural_i64(payload, member)?),
            "exp" => exp = parse_optional_structural_value(payload, member)?,
            "ref" | "ref_" => set_structural_once(
                &mut ref_,
                parse_optional_structural_string(payload, member)?,
            )?,
            _ => {}
        }
    }

    Ok(TrustMarkClaims {
        iss: iss.ok_or(FederationStructuralDecodeError::InvalidPayload)?,
        sub: sub.ok_or(FederationStructuralDecodeError::InvalidPayload)?,
        id: id.ok_or(FederationStructuralDecodeError::InvalidPayload)?,
        iat: iat.ok_or(FederationStructuralDecodeError::InvalidPayload)?,
        exp,
        ref_: ref_.flatten(),
    })
}

fn set_structural_once<T>(
    slot: &mut Option<T>,
    value: T,
) -> Result<(), FederationStructuralDecodeError> {
    if slot.replace(value).is_some() {
        Err(FederationStructuralDecodeError::DuplicateKey)
    } else {
        Ok(())
    }
}

fn decode_structural_key_bytes(raw_key: &[u8]) -> Result<String, FederationStructuralDecodeError> {
    let mut quoted = Vec::with_capacity(raw_key.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(raw_key);
    quoted.push(b'"');

    serde_json::from_slice::<String>(&quoted)
        .map_err(|_| FederationStructuralDecodeError::InvalidPayload)
}

fn structural_value_slice<'a>(
    payload: &'a [u8],
    member: &RawJsonStructuralMember,
) -> Result<&'a [u8], FederationStructuralDecodeError> {
    member
        .value_slice(payload)
        .ok_or(FederationStructuralDecodeError::Internal(
            "federation structural span out of bounds",
        ))
}

fn parse_required_structural_string(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<String, FederationStructuralDecodeError> {
    if member.value_kind != RawJsonStructuralValueKind::String {
        return Err(FederationStructuralDecodeError::InvalidPayload);
    }
    serde_json::from_slice(structural_value_slice(payload, member)?)
        .map_err(|_| FederationStructuralDecodeError::InvalidPayload)
}

fn parse_optional_structural_string(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Option<String>, FederationStructuralDecodeError> {
    match member.value_kind {
        RawJsonStructuralValueKind::Null => Ok(None),
        RawJsonStructuralValueKind::String => {
            serde_json::from_slice(structural_value_slice(payload, member)?)
                .map(Some)
                .map_err(|_| FederationStructuralDecodeError::InvalidPayload)
        }
        RawJsonStructuralValueKind::Number
        | RawJsonStructuralValueKind::Bool
        | RawJsonStructuralValueKind::Object
        | RawJsonStructuralValueKind::Array => Err(FederationStructuralDecodeError::InvalidPayload),
    }
}

fn parse_required_structural_i64(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<i64, FederationStructuralDecodeError> {
    if member.value_kind != RawJsonStructuralValueKind::Number {
        return Err(FederationStructuralDecodeError::InvalidPayload);
    }
    serde_json::from_slice(structural_value_slice(payload, member)?)
        .map_err(|_| FederationStructuralDecodeError::InvalidPayload)
}

fn parse_optional_structural_value<T: DeserializeOwned>(
    payload: &[u8],
    member: &RawJsonStructuralMember,
) -> Result<Option<T>, FederationStructuralDecodeError> {
    match member.value_kind {
        RawJsonStructuralValueKind::Null => Ok(None),
        RawJsonStructuralValueKind::String
        | RawJsonStructuralValueKind::Number
        | RawJsonStructuralValueKind::Bool
        | RawJsonStructuralValueKind::Object
        | RawJsonStructuralValueKind::Array => {
            let value = structural_value_slice(payload, member)?;
            validate_json_without_duplicate_object_keys(value).map_err(|err| match err {
                JsonAdmissionError::DuplicateKey => FederationStructuralDecodeError::DuplicateKey,
                JsonAdmissionError::InvalidJson | JsonAdmissionError::TrailingBytes => {
                    FederationStructuralDecodeError::InvalidPayload
                }
            })?;
            serde_json::from_slice(value)
                .map(Some)
                .map_err(|_| FederationStructuralDecodeError::InvalidPayload)
        }
    }
}

fn replay_serde_error_or<T: DeserializeOwned>(
    payload: &[u8],
    fallback: FederationError,
) -> FederationError {
    match serde_json::from_slice::<T>(payload) {
        Ok(_) => fallback,
        Err(err) => FederationError::Json(err),
    }
}

fn map_entity_statement_structural_parse_error(
    payload: &[u8],
    err: RawJsonStructuralParseError,
) -> FederationError {
    match err {
        RawJsonStructuralParseError::BufferTooLarge
        | RawJsonStructuralParseError::InvalidJson
        | RawJsonStructuralParseError::InvalidShape
        | RawJsonStructuralParseError::TrailingBytes => replay_serde_error_or::<EntityStatement>(
            payload,
            FederationError::Validation("raw-json-structural-invalid".into()),
        ),
        RawJsonStructuralParseError::ParserUnavailable => {
            FederationError::Validation("raw-json-structural-unavailable".into())
        }
        RawJsonStructuralParseError::Internal => {
            FederationError::Validation("raw-json-structural-internal".into())
        }
    }
}

fn map_entity_statement_structural_decode_error(
    payload: &[u8],
    err: FederationStructuralDecodeError,
) -> FederationError {
    match err {
        FederationStructuralDecodeError::DuplicateKey => {
            FederationError::Validation("duplicate-key".into())
        }
        FederationStructuralDecodeError::InvalidPayload => {
            replay_serde_error_or::<EntityStatement>(
                payload,
                FederationError::Validation("raw-json-structural-invalid".into()),
            )
        }
        FederationStructuralDecodeError::Internal(message) => {
            FederationError::Validation(message.to_string())
        }
    }
}

fn map_trust_mark_structural_parse_error(
    payload: &[u8],
    err: RawJsonStructuralParseError,
) -> FederationError {
    match err {
        RawJsonStructuralParseError::BufferTooLarge
        | RawJsonStructuralParseError::InvalidJson
        | RawJsonStructuralParseError::InvalidShape
        | RawJsonStructuralParseError::TrailingBytes => replay_serde_error_or::<TrustMarkClaims>(
            payload,
            FederationError::TrustMark("raw-json-structural-invalid".into()),
        ),
        RawJsonStructuralParseError::ParserUnavailable => {
            FederationError::TrustMark("raw-json-structural-unavailable".into())
        }
        RawJsonStructuralParseError::Internal => {
            FederationError::TrustMark("raw-json-structural-internal".into())
        }
    }
}

fn map_trust_mark_structural_decode_error(
    payload: &[u8],
    err: FederationStructuralDecodeError,
) -> FederationError {
    match err {
        FederationStructuralDecodeError::DuplicateKey => {
            FederationError::TrustMark("duplicate-key".into())
        }
        FederationStructuralDecodeError::InvalidPayload => {
            replay_serde_error_or::<TrustMarkClaims>(
                payload,
                FederationError::TrustMark("raw-json-structural-invalid".into()),
            )
        }
        FederationStructuralDecodeError::Internal(message) => {
            FederationError::TrustMark(message.to_string())
        }
    }
}
